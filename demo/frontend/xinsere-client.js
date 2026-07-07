/* Xinsere client-side reassembly — reusable, framework-free.
 *
 * Consumes a "retrieval plan" from the API (per-fragment presigned GET URLs +
 * base64 data keys/nonces) and rebuilds the file entirely in the browser:
 *
 *   fetch fragments in parallel (straight from storage, not via the API server)
 *     -> AES-256-GCM decrypt each with WebCrypto
 *     -> join in sequence -> SHA-256 verify -> Blob
 *
 * The plaintext never exists on the server. Designed for reuse by the web app,
 * the future SDK, and the MCP client.
 *
 * Resilience (unreliable networks are the normal case):
 *   - each fragment fetch retries up to `retries` times with exponential backoff
 *   - a partial body resumes from the last received byte via HTTP Range, so a
 *     dropped connection re-fetches only the missing tail — never the whole file
 *   - fragments are independent units; a failure on one never invalidates others
 *   - every fragment is authenticated (GCM tag) and the whole file SHA-256
 *     verified, so resumed/retried bytes cannot go undetected if corrupted
 *
 * API:
 *   XinsereClient.reassemble(plan, {onStage, onProgress, retries, concurrency})
 *     -> Promise<{blob, sha256}>   (throws on integrity failure)
 */
(function (global) {
  "use strict";

  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  /* Fetch one fragment with retry + Range resume. Returns Uint8Array of the
   * complete ciphertext. `onBytes(delta)` reports newly received bytes (may be
   * called again with a negative correction if a resume restarts a chunk).
   *
   * Short reads are NOT success: if the stream ends before Content-Length /
   * Content-Range total, that's an early EOF (network drop, server hangup) and
   * we resume from the last byte via Range. Without this, truncated ciphertext
   * only surfaces later as a GCM auth failure. */
  async function fetchFragment(url, onBytes, retries, diag) {
    const chunks = [];
    let got = 0;
    let expected = 0; // total fragment size, learned from the first response
    for (let attempt = 0; ; attempt++) {
      try {
        const headers = got > 0 ? { Range: `bytes=${got}-` } : {};
        const r = await fetch(url, { headers });
        // Order matters: an ERROR response on a resume must NOT wipe the bytes we
        // already have — we keep them and resume again. Only a genuine 200 (server
        // ignored Range and is re-sending the full body) restarts the fragment.
        if (!r.ok && r.status !== 206) throw new Error("fragment GET " + r.status);
        if (got > 0 && r.status === 200) {
          diag && diag({ event: "range-ignored", had: got });
          onBytes(-got); chunks.length = 0; got = 0;
        }
        if (!expected) {
          if (r.status === 206) {
            const m = /\/(\d+)\s*$/.exec(r.headers.get("Content-Range") || "");
            if (m) expected = parseInt(m[1], 10);
          } else {
            expected = parseInt(r.headers.get("Content-Length") || "0", 10);
          }
        }
        const reader = r.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value); got += value.length; onBytes(value.length);
        }
        if (expected && got < expected) {
          throw new Error(`short read: ${got}/${expected} bytes`); // retryable — resumes via Range
        }
        const out = new Uint8Array(got);
        let pos = 0;
        for (const c of chunks) { out.set(c, pos); pos += c.length; }
        return out;
      } catch (e) {
        diag && diag({ event: "retry", attempt: attempt + 1, got, expected, error: String(e.message || e) });
        if (attempt >= retries) throw e;
        if (typeof console !== "undefined") console.debug("xinsere: fragment retry", attempt + 1, e.message || e);
        // Exponential backoff with jitter; partial bytes are kept — the next
        // attempt resumes from `got` via Range.
        await sleep(Math.min(8000, 400 * 2 ** attempt) + Math.random() * 300);
      }
    }
  }

  async function decryptFragment(cipher, keyB64, nonceB64) {
    const key = await crypto.subtle.importKey("raw", b64(keyB64), "AES-GCM", false, ["decrypt"]);
    // cryptography's AESGCM outputs ciphertext||tag(16B) — WebCrypto expects the same.
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64(nonceB64), tagLength: 128 }, key, cipher);
    return new Uint8Array(plain);
  }

  const toHex = (buf) =>
    [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

  async function reassemble(plan, opts) {
    // concurrency defaults to 4: reduces parallel-stream churn on big fragments
    // (browser + S3 cope better than 7+ simultaneous 25MB bodies) at negligible
    // wall-clock cost since bandwidth is shared anyway.
    const { onStage = () => {}, onProgress = () => {}, retries = 3,
            concurrency = 4 } = opts || {};
    const total = plan.size || 0;
    let received = 0;
    const onBytes = (d) => { received += d; onProgress(received, total); };

    // Diagnostic trail: every retry / range-reset / failure per fragment, so a
    // failed download can report exactly what went wrong (attached to the error).
    const events = [];
    const diagFor = (seq) => (e) => {
      events.push({ seq, t: Math.round(performance.now()), ...e });
    };

    onStage("fetch", `Fetching ${plan.fragments.length} fragments in parallel…`);
    const frags = plan.fragments.slice().sort((a, b) => a.sequence - b.sequence);

    const plains = new Array(frags.length);
    let next = 0;
    async function worker() {
      while (next < frags.length) {
        const i = next++;
        const f = frags[i];
        const cipher = await fetchFragment(f.url, onBytes, retries, diagFor(f.sequence));
        onStage("decrypt", `Decrypting fragment ${f.sequence + 1}/${frags.length}…`);
        plains[i] = await decryptFragment(cipher, f.key, f.nonce);
      }
    }
    try {
      await Promise.all(
        Array.from({ length: Math.min(concurrency, frags.length) }, worker));
    } catch (e) {
      e.xinsereEvents = events;  // carry the trail out for logging
      throw e;
    }

    onStage("verify", "Verifying whole-file SHA-256…");
    let size = 0;
    for (const p of plains) size += p.length;
    const joined = new Uint8Array(size);
    let pos = 0;
    for (const p of plains) { joined.set(p, pos); pos += p.length; }

    const sha = toHex(await crypto.subtle.digest("SHA-256", joined));
    if (plan.sha256 && sha !== plan.sha256) {
      const err = new Error("reassembled file failed SHA-256 verification");
      err.xinsereEvents = events;
      throw err;
    }
    return {
      blob: new Blob([joined], { type: plan.content_type || "application/octet-stream" }),
      sha256: sha,
    };
  }

  global.XinsereClient = { reassemble };
})(typeof window !== "undefined" ? window : globalThis);
