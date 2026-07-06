# Deploying the Xinsere Demo (v2 — hosted, real accounts)

The demo now has real accounts (self-serve signup + login, SQLite, hashed
passwords) and is container-ready. This guide gets it onto a public HTTPS URL so
J & J — and anyone — can use it from their own machines.

## What changed from v1

- **Real logins:** `auth.py` (SQLite + PBKDF2). Signup on the login screen.
  The 3 demo users (mark/jeremy/joshua, pw `xinsere`) are seeded so the old flow
  still works; new users sign up with email + password.
- **Config via env:** `XINSERE_DATA_DIR`, `XINSERE_SESSION_SECRET`,
  `XINSERE_PRIVATE_KEY` (Amoy signer), `AWS_REGION`.
- **Container:** `Dockerfile` + `render.yaml` at the repo root.

## Environment variables

| Var | Purpose | Notes |
|-----|---------|-------|
| `XINSERE_DATA_DIR` | where users.db + fragments + index live | mount a persistent volume here |
| `XINSERE_SESSION_SECRET` | signs session cookies | random per deploy |
| `XINSERE_PRIVATE_KEY` | Amoy signer for on-chain grants | **burned testnet key only**, set as a secret |
| `AWS_REGION` | only if using Secrets Manager instead of the key env | default us-east-1 |

**Signer:** off AWS there's no IAM role, so set `XINSERE_PRIVATE_KEY` (the testnet
wallet `0x70B1…`). Keep it funded with Amoy POL for gas. `chain.py` already prefers
this env var over Secrets Manager.

## Option A — Render (simplest)

1. Push the repo to GitHub (done: `MkTurner74/xinsere-v2`).
2. Render → **New → Blueprint** → pick the repo → it reads `render.yaml`.
3. Set `XINSERE_PRIVATE_KEY` in the dashboard (Environment → Secret).
4. Deploy. Render gives an HTTPS URL (`https://xinsere-demo.onrender.com`).
5. Send J & J the URL — they sign up and use it.

*A paid Starter instance is needed for the persistent disk.*

## Option B — Fly.io

```bash
fly launch --dockerfile Dockerfile --now=false
fly volumes create xinsere_data --size 1
# fly.toml: mount xinsere_data -> /data ; set XINSERE_DATA_DIR=/data
fly secrets set XINSERE_PRIVATE_KEY=0x... XINSERE_SESSION_SECRET=$(openssl rand -hex 32)
fly deploy
```

## Option C — Docker anywhere

```bash
docker build -t xinsere-demo .          # from repo root
docker run -p 8000:8000 \
  -v xinsere-data:/data \
  -e XINSERE_PRIVATE_KEY=0x... \
  -e XINSERE_SESSION_SECRET=$(openssl rand -hex 32) \
  xinsere-demo
```

## Before you share it

- [ ] `XINSERE_PRIVATE_KEY` set to the **testnet** wallet; wallet funded with Amoy POL
- [ ] Persistent volume mounted at `XINSERE_DATA_DIR` (else data resets on redeploy)
- [ ] `XINSERE_SESSION_SECRET` set (random)
- [ ] Test: sign up a fresh account, upload, share to another account, download

## Still demo-grade (call out before wider use)

- No email verification / password reset yet.
- Storage uses the local pipeline backends on the server's disk (not yet S3/KMS/
  DynamoDB — that swap comes with the P0 infra).
- One signer wallet for all on-chain grants (fine for a shared testnet demo).
