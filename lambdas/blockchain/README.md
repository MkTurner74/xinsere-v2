# Xinsere Blockchain Permission Service

The Node.js backend that turns the deployed **XinserePermissions** contract into a
usable permission layer: grant / revoke / verify / audit, with the wallet held in
AWS Secrets Manager and every write signed server-side.

- **Contract (Amoy):** `0xf2978c58Ec46103FC2110575DFd62cf3ba997FCD`
- **Network:** Polygon Amoy testnet (chain 80002)
- **Wallet:** `0x70B1D5618d302b0c4599365C419156627b07fd04` (owner + admin)

## Layout

```
src/
  config.ts       env + Amoy-correct defaults
  abi.ts          contract interface (grant/revoke/verify/audit)
  hashing.ts      fileHash = SHA256(content) · granteeHash = HMAC-SHA256(id, salt)
  wallet.ts       Secrets Manager key fetch (env fallback for local dev)
  permissions.ts  PermissionService — the backend wrapper
  handler.ts      Lambda entry (action-routed; hashes opaque ids for callers)
test/
  chain.ts        end-to-end test against live Amoy
```

## Setup

```bash
cd lambdas/blockchain
npm install
cp .env.example .env    # defaults already point at the live Amoy contract
```

The wallet is read from Secrets Manager (`xinsere/blockchain/polygon-mumbai/private-key`)
using your AWS credentials. If you don't have AWS creds handy for a quick local run,
set `XINSERE_PRIVATE_KEY` in `.env` as a dev-only fallback.

## Test the whole chain

```bash
npm run test:smoke   # read-only: connectivity, owner/admin, verify — FREE
npm test             # full lifecycle: grant -> verify -> audit -> revoke (costs a little POL)
```

`npm test` proves the entire path end-to-end: Secrets Manager → signer → on-chain
grant → verify true → audit trail → revoke → verify false.

## Key facts baked in

- **Amoy gas floor:** every write sets a ≥25 gwei priority fee (default 30/50 gwei),
  or the network rejects it with *"gas price below minimum."*
- **Nothing sensitive on-chain:** only hashes. The service never sees raw files or
  plaintext identities — callers pass opaque `fileId` / `granteeId`, hashed here.
- **Key never logged:** the private key is fetched into memory and used only to sign.

## Known contract limitations (tracked for later)

- `checkFileExists` is a placeholder that always returns `true`.
- Re-granting the same (file, grantee) silently overwrites the prior record.
- The `bytes32` a write returns is a keccak of inputs, **not** the tx hash — read the
  receipt (`WriteResult.txHash`) for the real one.
