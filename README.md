# Xinsere v2 — Distributed Permissioned Data (DPD)

**Botverse Secure** — encrypted storage and provable permission management for AI agents and human users.

> Every AI tool can generate a convincing fake document. Xinsere is the only place you can prove yours is real.

---

## What this is

Xinsere is a serverless, blockchain-permissioned file storage system. Files are:

- Fragmented into N chunks
- Each fragment encrypted with an independent AES-256 KMS data key
- Distributed across multiple S3 buckets in different locations
- Indexed with a blockchain-immutable permission audit trail on Polygon PoS

No single fragment is useful without the others. No key decrypts more than one fragment. Xinsere's infrastructure cannot decrypt your files — even under compulsion.

---

## Products

| Product | Surface | Audience |
|---|---|---|
| **Botverse Secure** | MCP server (`@botverse/secure`) | AI agent developers (Claude, LangChain, CrewAI, n8n) |
| **Xinsere Business** | Web file browser + REST API | Teams in healthcare, legal, financial services |
| **Xinsere Enterprise** | BYOK/BYOB/self-hosted + Marketplace | Regulated enterprise, government |

---

## MCP tools

```
secure_store    — store a file with per-fragment encryption
secure_retrieve — retrieve a file (if caller has permission)
secure_grant    — grant a party permission to a file
secure_revoke   — revoke a permission
secure_verify   — verify a permission (3rd-party audit)
secure_audit    — pull full audit trail for a file
```

---

## Architecture

Serverless AWS — 5 core Lambda functions (Python), 8 management Lambdas (Python), 1 blockchain Lambda (Node.js). API Gateway + Cognito auth. Polygon PoS for the permission ledger. MySQL RDS for the file tree. DynamoDB for fragment index and metadata.

Full architecture: [docs/PRD.md](docs/PRD.md)

---

## Status

**Pre-build.** Phase 0 (security cleanup) in progress. See [docs/PRD.md](docs/PRD.md) for build plan and testing matrix.

---

## Repo structure

```
docs/
  PRD.md              — full product design, build plan, testing matrix, security audit
lambdas/              — Lambda function source code (Phase 1+)
mcp-server/           — TypeScript MCP server (Phase 4)
frontend/             — React file browser (Phase 5)
infrastructure/       — CloudFormation templates
contracts/            — Solidity smart contracts
tests/                — Integration and security test suite
```

---

## Co-founders

Mark Turner, Jeremy Katz, Joshua Katz

Botverse brand: Entertainment Technologists Dev Corp / ReallyUs LLC

*Transfer this repo to the botverse GitHub org once created at github.com/organizations/new*
