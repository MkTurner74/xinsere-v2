# Xinsere Desktop — App-First Native Client (Design Record)

*2026-07-15 — design decisions + estimates. Not scheduled for build.*
*Full research (platform APIs, vendor evidence, store policy, 40 sources): `Ai Companion Docs/references/research/2026-07-15-xinsere-desktop-integration.md`*
*Scope: USER-level only (browse, view, upload, download, share, edit round-trip, offline). Admin stays on the web app.*

---

## The decision

**Build a standalone desktop app ("Xinsere Desktop"), NOT Windows Explorer / macOS Finder sync integration.**

Rationale chain (each step decided 2026-07-15, Mark):

1. Universal watermarking (owners/admins included) forbids byte-identical Dropbox-style sync — the sync client would be the exfiltration path that voids the forensic story.
2. Therefore local copies of others' files would be per-user+device *watermarked renditions*, and view-only files would never hydrate — viewing happens in OUR viewer regardless.
3. Once viewing is in-app and local copies are derivatives, testing every web capability against "needs OS level?" leaves exactly one row: native-app editing round-trip.
4. **Edit-session checkout** (Box Edit pattern, §Edit sessions below) closes that row without OS integration and without per-app plugins.
5. What Explorer/Finder integration retains is ambience only (presence in Explorer sidebar and other apps' Open/Save dialogs) — at the cost of the two hardest components in the study (Cloud Filter API + File Provider), permanent OS-release maintenance, and platform CVE exposure.
6. Bonus: Office real-time co-authoring is impossible in ANY architecture except M365-backed storage — OS integration never buys it. Argument closed.

OS integration is **deferred, not dead**: it returns as a paid power feature on the same Rust core if a customer segment proves a need the session model can't cover. The research brief Parts B–D are the ready design record for that phase.

## Product shape

Xinsere Desktop = the web experience, native, plus three things the browser can't do:

| Pillar | What it is |
|---|---|
| **Navigation & management** | Everything the web app does today (tree, search, share/revoke, move/rename/trash, bulk ops, provenance) — same API, same UI patterns |
| **Secure viewer** | The existing server-mediated watermarked viewer, in-app |
| **Encrypted offline vault** | Files the user pins for offline: stored AES-encrypted at rest in app storage, keys in OS keystore (DPAPI / Keychain), decrypted only in-app for viewing. Nothing Xinsere-owned ever sits in the open filesystem. Strictly better than sync-style hydration. |
| **Entitled Export** | The only way bytes leave the vault: explicit, permission-checked, logged, forensically watermarked (user + org + **device** + timestamp + node) |
| **Edit-session checkout** | Native-app round-trip without plugins (below) |

### Edit sessions (the Word/Photoshop answer)

No Office add-ins, no UXP panels, no Avid plugins — native apps only need a local path:

1. "Edit in Word…" (entitlement-checked, logged) → working copy into an app-controlled dir → open with OS default handler.
2. App watches the file (`ReadDirectoryChangesW`/FSEvents; handle Office's atomic save-via-rename) and tracks the editor process.
3. Every save → new immutable version through the normal pipeline (fragment, encrypt, hash, anchor), debounced. Advisory "being edited by X" flag on the node.
4. Session end → final version confirmed, working copy shredded, vault-only again.

Honest limits (same in every architecture): the working copy is a plain file *during* the session (bounded + shredded, vs indefinite under sync hydration); Save-As-elsewhere can't be blocked (it's an entitled, marked copy — that's what the forensic model is for); NLE masters don't round-trip through any vault — proxies/review in viewer + managed export is the M&E answer.

### Sync-back & conflicts

Immutable content-addressed versions ⇒ no merge, only lineage. Last-writer-wins on the "current" pointer, both versions kept, "Conflicted copy from DEVICE" badge. Never destroys data. No CRDTs (opaque media binaries don't line-merge).

### Offline

- Vault items: viewable offline (decrypt in-app). Placeholder-only items: not available offline, say why.
- Grants enforced at the API on every retrieval; offline exposure window = already-vaulted items only, covered by the mark.
- Offline uploads queue + anchor on reconnect, surfaced honestly as "pending secure upload"; consider refusing queue into shared folders (grant-on-add lag).
- Audit honesty: the access log covers *retrievals* (hourly Merkle-anchored), not local opens.

### Chain

Stays server-side. The app is an API client; the contract remains authoritative at the only enforceable point (the reassembly service). Share/revoke from the app = existing `/api/share`/`/api/unshare` batch-grant paths. No wallet, no tokens, no balances anywhere in the client — also de-risks store review if we ever distribute via stores.

## Architecture

- **Shell: Tauri** (Rust host + system webview). The Rust host grows into the shared core (crypto, fragment reassembly, Merkle proof handling, vault, upload queue, edit-session watcher) that later powers iOS/Android and any future OS integration. Electron is the fallback if webview parity bites.
- **UI: the existing web front end** (`demo/frontend/index.html` app) loaded in the shell — most of the product already exists; desktop-only surfaces (vault manager, edit sessions, settings) added incrementally.
- **Reuse math** (research Part C): ~70–85% of non-UI logic shared across desktop + mobile; if OS integration is ever built, only the CfAPI/FileProvider shims are new.

## Estimates

Two honest scales — classic engineering estimates (research-derived) and this project's observed Claude-assisted pace (the whole current product was built at ~1 major feature set/day):

| Milestone | Contents | Classic estimate | This project's pace |
|---|---|---|---|
| **P0 — Prototype (demo-grade, Windows first)** | Tauri shell + auth + existing web UI; vault v0 (encrypt-at-rest, DPAPI, offline view of pinned files); Export with device-ID mark (small server change); edit-session v0 (Word round-trip: watch → version-upload → shred); dev-signed only | ~5–7 weeks, 1 engineer | **~1–2 weeks of sessions** |
| **P1 — macOS parity** | Same codebase; Keychain, FSEvents, notarization + Developer ID ($99/yr, no Mac App Store needed) | +2–3 weeks | +2–4 sessions |
| **P2 — Production beta (both OSes)** | Hardening, auto-update, code signing + SmartScreen ramp (~$300–600/yr cert or Azure Trusted Signing), crash/telemetry, conflict UX, editing locks, queue robustness, pentest round ($15–30k) | 2–3 engineers × 4–6 months | n/a — this tier needs real QA + signing infra regardless of authoring speed |
| *(deferred)* OS sync integration | CfAPI + File Provider per research Parts B/D | 4–6 eng × 9–12 months + permanent maintenance | not recommended |

Pre-requisites already true: `/v1` API + web UI cover ~all P0 server needs. Server-side additions for P0: hydrate/export endpoint variant carrying device ID in the forensic payload; advisory edit-lock flag; (optional) egress quota extension to desktop clients.

## Open decisions (founders)

1. Approve app-first (this doc) vs OS-integration-first — recommended: app-first.
2. Approve watermark policy application: vault + entitled marked Export only; view-only never leaves the viewer.
3. Patent counsel: watermark-at-hydration / vault-with-entitled-export in a desktop client context — ask BEFORE public disclosure or any P0 demo outside NDA.
4. P0 timing — not scheduled; prototype is 1–2 Claude-assisted weeks when wanted (e.g., ahead of an acquirer demo).
