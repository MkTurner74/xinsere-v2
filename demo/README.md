# Xinsere Demo — Secure File Explorer

A working, wired demo of the Xinsere flow for the J & J status call:

1. **Drag & drop** a file (or a whole folder) — it's fragmented + AES-256 encrypted
   by the real pipeline before storage.
2. **Share** a file or folder with Jeremy or Joshua — writes a **real grant on the
   Polygon Amoy contract**.
3. They **sign in from their own machine, browse the tree, and download** — access
   is decided by an **on-chain `verify()` call**, then the file is reassembled and
   SHA-256 verified.

## This is genuinely blockchain-gated

Download permission is **not** a local flag. The server calls the deployed
`XinserePermissions` contract (`0xf2978c58Ec46103FC2110575DFd62cf3ba997FCD`) on
Amoy to decide access. The demo DB only stores the folder tree + a mirror of who
was shared (for the file listing) — never the access decision.

- Share → real Amoy tx (viewable on PolygonScan)
- Download → contract `verify(fileHash, granteeHash)` must return true
- Revoke on-chain → download stops working immediately

## Run it

```powershell
cd demo
.\run.ps1        # creates venv, installs deps, starts on :8000
```

Open http://127.0.0.1:8000 — **sign up** for a real account, or sign in as a
seeded demo user **mark** / **jeremy** / **joshua** (password **xinsere**).

**Real accounts (v2):** signup + login with email/password (SQLite, hashed) —
see `auth.py`. To host it publicly so others can use it with their own logins,
see **DEPLOY.md** (Render / Fly / Docker).

**Prereq:** be signed in to the Xinsere AWS account (`aws sts get-caller-identity`
→ `058264449111`). On-chain grants read the signer key from Secrets Manager, and
the signer wallet needs a little Amoy POL for gas.

## Show two sides at once

Open a second **incognito/other browser** as Jeremy. Share from Mark's window →
refresh Jeremy's "Shared with me" → download. That's the whole story live.

## Let J & J join from their machines

Expose the local server with a tunnel and send them the URL:

```powershell
# Cloudflare (no account needed for a quick tunnel):
cloudflared tunnel --url http://localhost:8000
# or ngrok:  ngrok http 8000
```

## Architecture

- `app.py` — FastAPI routes (auth, tree, upload, folder, share, verify, download)
- `demo_store.py` — file tree + shares + JSON-persisted pipeline index
- `chain.py` — real Amoy grant/verify (web3 + Secrets Manager signer)
- `frontend/index.html` — branded file-explorer UI
- Storage: the actual `lambdas/pipeline` (local backends, persisted to `data/`)

## Notes / limits (demo stage)

- Basic session auth, 3 fixed users. Not production auth.
- Sharing a folder grants each file under it on-chain at share time (a few seconds
  per file). Files added *after* a folder is shared aren't auto-granted yet.
- Pipeline uses local backends; swaps to real S3/KMS/DynamoDB when P0 infra lands.
