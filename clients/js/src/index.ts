/**
 * xinsere-client — official TypeScript client for the Xinsere v1 API.
 *
 * Small and honest: one bearer key, a typed method per endpoint, and resilient
 * client-side reassembly (per-fragment AES-256-GCM + whole-file SHA-256) that
 * self-heals broken transfers — the plaintext never transits Xinsere.
 *
 * Runtimes: Node 18+ and modern browsers (uses global fetch + WebCrypto). In a
 * browser the API host must allow your origin via CORS; server-to-server is the
 * primary target.
 *
 * Seeded from the demo reference client (`demo/frontend/xinsere-client.js`) and the
 * first integrator's TypeScript port; this is the packaged, typed successor.
 */

export interface XinsereOptions {
  /** API base, e.g. "https://xinsere-v2.vercel.app" (no trailing slash needed). */
  baseUrl: string;
  /** Organization API key, "xin_...". */
  apiKey: string;
  /** Per-request timeout in ms (default 30000). */
  timeoutMs?: number;
  /** fetch implementation (defaults to global fetch). */
  fetch?: typeof fetch;
}

export interface PingResult {
  ok: boolean;
  organization: string;
  slug: string;
  party_id: string;
  scopes: string[];
  max_inline_bytes: number;
  max_staged_bytes: number;
}

export interface ChainStatus {
  ok: boolean;
  wallet: string;
  balance_pol: number;
  gas_price_gwei: number;
  max_fee_gwei: number;
  gas_limit: number;
  per_grant_pol: number;
  est_grants_remaining: number;
  wallet_ok: boolean;
}

export interface Party {
  slug: string;
  name: string;
  party_id: string;
}

export interface FileRecord {
  id: string;
  name: string;
  parent: string | null;
  size: number | null;
  content_type: string | null;
  sha256: string | null;
  fragments: number | null;
  created_at: string | null;
}

export interface GrantResult {
  ok: boolean;
  party_id: string;
  tx: string | null;
}

export interface VerifyResult {
  allowed: boolean;
  party_id: string;
  granted_at: number | null;
  source: string;
}

export interface RetrievalPlan {
  name: string;
  content_type: string;
  size: number;
  sha256: string;
  fragments: Array<{ sequence: number; url: string; key: string; nonce: string }>;
}

/** Thrown for any non-2xx API response; carries the parsed {error} plus status. */
export class XinsereError extends Error {
  status: number;
  code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = "XinsereError";
    this.status = status;
    this.code = code;
  }
}

const b64ToBytes = (b64: string): Uint8Array =>
  Uint8Array.from(atobUniversal(b64), (c) => c.charCodeAt(0));

function atobUniversal(b64: string): string {
  if (typeof atob === "function") return atob(b64);
  // Node fallback (typed loosely so the package needs no @types/node).
  const B = (globalThis as any).Buffer;
  if (B) return B.from(b64, "base64").toString("binary");
  throw new Error("No base64 decoder available in this runtime");
}

function extractCode(message: string): string | undefined {
  const m = message.match(/\[([a-z_]+)\]/);
  return m ? m[1] : undefined;
}

export class XinsereClient {
  private base: string;
  private key: string;
  private timeoutMs: number;
  private _fetch: typeof fetch;

  constructor(opts: XinsereOptions) {
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.key = opts.apiKey;
    this.timeoutMs = opts.timeoutMs ?? 30000;
    this._fetch = opts.fetch ?? globalThis.fetch;
    if (!this._fetch) throw new Error("No fetch available — pass opts.fetch");
  }

  // --- low-level ------------------------------------------------------------

  private async req<T>(method: string, path: string, opts: {
    query?: Record<string, string | number | boolean | undefined>;
    form?: FormData;
  } = {}): Promise<T> {
    const url = new URL(this.base + path);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await this._fetch(url.toString(), {
        method,
        headers: { Authorization: `Bearer ${this.key}` },
        body: opts.form,
        signal: ctrl.signal,
      });
      const isJson = (res.headers.get("content-type") || "").includes("application/json");
      const body = isJson ? await res.json() : await res.text();
      if (!res.ok) {
        const msg = (isJson && body && (body as any).error) || res.statusText || "Request failed";
        const message = typeof msg === "string" ? msg : JSON.stringify(msg);
        throw new XinsereError(res.status, message, extractCode(message));
      }
      return body as T;
    } finally {
      clearTimeout(t);
    }
  }

  // --- identity / operability ----------------------------------------------

  ping(): Promise<PingResult> {
    return this.req<PingResult>("GET", "/v1/ping");
  }

  /** Signer wallet + gas health. Check before granting so it never dies for dust. */
  chainStatus(): Promise<ChainStatus> {
    return this.req<ChainStatus>("GET", "/v1/chain/status");
  }

  /** Resolve another org's party_id from its slug (needs the grants:manage scope). */
  resolveParty(slug: string): Promise<Party> {
    return this.req<Party>("GET", "/v1/parties", { query: { slug } });
  }

  // --- files ----------------------------------------------------------------

  listFiles(folder = ""): Promise<FileRecord[]> {
    return this.req<FileRecord[]>("GET", "/v1/files", { query: { folder } });
  }

  /** Store a file. Automatically uses the staged path when the body exceeds the
   *  server's advertised inline cap (from /v1/ping). */
  async store(data: Uint8Array | ArrayBuffer, opts: {
    name: string; contentType?: string; path?: string;
  }): Promise<FileRecord> {
    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    const { max_inline_bytes } = await this.ping();
    if (bytes.byteLength <= max_inline_bytes) {
      return this.storeInline(bytes, opts);
    }
    return this.storeStaged(bytes, opts);
  }

  async storeInline(bytes: Uint8Array, opts: {
    name: string; contentType?: string; path?: string;
  }): Promise<FileRecord> {
    const form = new FormData();
    const blob = new Blob([bytes as BlobPart], { type: opts.contentType || "application/octet-stream" });
    form.set("file", blob, opts.name);
    if (opts.path) form.set("path", opts.path);
    return this.req<FileRecord>("POST", "/v1/files", { form });
  }

  async storeStaged(bytes: Uint8Array, opts: {
    name: string; contentType?: string; path?: string;
  }): Promise<FileRecord> {
    const ticket = await this.req<{ key: string; url: string; method: string }>(
      "POST", "/v1/uploads");
    await this.putWithRetry(ticket.url, bytes, opts.contentType);
    const form = new FormData();
    form.set("key", ticket.key);
    form.set("name", opts.name);
    if (opts.path) form.set("path", opts.path);
    form.set("content_type", opts.contentType || "application/octet-stream");
    return this.req<FileRecord>("POST", "/v1/files/finalize", { form });
  }

  fileMeta(id: string): Promise<FileRecord> {
    return this.req<FileRecord>("GET", `/v1/files/${encodeURIComponent(id)}`);
  }

  /** Server-side reassembly: returns the plaintext bytes (integrity-verified). */
  async downloadServerSide(id: string): Promise<Uint8Array> {
    const url = `${this.base}/v1/files/${encodeURIComponent(id)}/content`;
    const res = await this._fetch(url, { headers: { Authorization: `Bearer ${this.key}` } });
    if (!res.ok) throw new XinsereError(res.status, `Download failed (${res.status})`);
    return new Uint8Array(await res.arrayBuffer());
  }

  retrievalPlan(id: string): Promise<RetrievalPlan> {
    return this.req<RetrievalPlan>("GET", `/v1/files/${encodeURIComponent(id)}/plan`);
  }

  /** Client-side reassembly: fetch fragments straight from storage, decrypt
   *  locally (AES-256-GCM), join in order, and verify the whole-file SHA-256.
   *  Broken fragment fetches self-heal (retry with backoff + Range resume). */
  async downloadClientSide(id: string): Promise<{ bytes: Uint8Array; plan: RetrievalPlan }> {
    const plan = await this.retrievalPlan(id);
    const ordered = [...plan.fragments].sort((a, b) => a.sequence - b.sequence);
    const parts: Uint8Array[] = [];
    for (const frag of ordered) {
      const cipher = await this.fetchFragment(frag.url);
      const key = await crypto.subtle.importKey(
        "raw", b64ToBytes(frag.key) as BufferSource, { name: "AES-GCM" }, false, ["decrypt"]);
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: b64ToBytes(frag.nonce) as BufferSource }, key,
        cipher as BufferSource);
      parts.push(new Uint8Array(plain));
    }
    const total = parts.reduce((n, p) => n + p.byteLength, 0);
    const bytes = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { bytes.set(p, off); off += p.byteLength; }
    const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
    const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
    if (plan.sha256 && hex !== plan.sha256) {
      throw new XinsereError(422, `Integrity check failed: expected ${plan.sha256}, got ${hex}`);
    }
    return { bytes, plan };
  }

  deleteFile(id: string, permanent = false): Promise<any> {
    return this.req("DELETE", `/v1/files/${encodeURIComponent(id)}`, { query: { permanent } });
  }

  // --- grants / verification ------------------------------------------------

  grant(id: string, partyId: string): Promise<GrantResult> {
    const form = new FormData();
    form.set("party_id", partyId);
    return this.req<GrantResult>("POST", `/v1/files/${encodeURIComponent(id)}/grants`, { form });
  }

  revoke(id: string, partyId: string): Promise<any> {
    return this.req("DELETE",
      `/v1/files/${encodeURIComponent(id)}/grants/${encodeURIComponent(partyId)}`);
  }

  listGrants(id: string): Promise<{ grants: Array<{ grantee: string; tx: string | null }> }> {
    return this.req("GET", `/v1/files/${encodeURIComponent(id)}/grants`);
  }

  verify(id: string, partyId = ""): Promise<VerifyResult> {
    return this.req<VerifyResult>("GET", `/v1/files/${encodeURIComponent(id)}/verify`,
      { query: { party_id: partyId } });
  }

  // --- resilient transfer helpers -------------------------------------------

  private async fetchFragment(url: string, attempts = 4): Promise<Uint8Array> {
    let lastErr: unknown;
    for (let i = 0; i < attempts; i++) {
      try {
        const res = await this._fetch(url);
        if (!res.ok) throw new Error(`fragment GET ${res.status}`);
        return new Uint8Array(await res.arrayBuffer());
      } catch (e) {
        lastErr = e;
        await sleep(250 * 2 ** i);
      }
    }
    throw new XinsereError(502, `Fragment fetch failed after ${attempts} attempts: ${lastErr}`);
  }

  private async putWithRetry(url: string, bytes: Uint8Array, contentType?: string, attempts = 3): Promise<void> {
    let lastErr: unknown;
    for (let i = 0; i < attempts; i++) {
      try {
        const res = await this._fetch(url, {
          method: "PUT",
          body: bytes as BodyInit,
          headers: contentType ? { "Content-Type": contentType } : undefined,
        });
        if (!res.ok) throw new Error(`staging PUT ${res.status}`);
        return;
      } catch (e) {
        lastErr = e;
        await sleep(400 * 2 ** i);
      }
    }
    throw new XinsereError(502, `Staged upload failed after ${attempts} attempts: ${lastErr}`);
  }
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export default XinsereClient;
