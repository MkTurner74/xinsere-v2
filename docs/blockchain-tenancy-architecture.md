# Xinsere — Wallet, Gas & On-Chain Tenant-Isolation Architecture

*Decision memo · 2026-07-11 · SaaS tier vs Enterprise tier. Based on a deep-research
pass (sources at end) + the on-chain metadata question raised during Samsyn testing.
Raw research: `blockchain-tenancy-supporting-research-2026-07-11.md`.*

## TL;DR — your instinct is right on both counts

1. **Enterprise: yes — they bring their own wallet, pay their own gas, and (for the
   privacy-sensitive ones) run on their own permissioned chain, not our public one.**
   That is the industry-standard enterprise pattern (bring-your-own-keys +
   bring-your-own-chain), and it's already what your PRD anticipated (Fabric enterprise
   tier + public-audit anchoring). The research validates it.
2. **SaaS: no — do not take the current "one platform wallet → one shared public
   contract" model to production.** It's the weakest isolation pattern there is
   ("pooled / fully-shared"): one key = whole-platform blast radius, and every
   customer's activity co-mingles on one public page — exactly what you saw. The fix
   is cheap and high-leverage.

The right answer is a **two-tier design with a phased rollout**, not one wallet model.

---

## Why the current model is the weak end of the spectrum

A single signer writing every customer's grants to one shared contract is, in
multi-tenancy terms, the "fully shared / pooled" model — the lowest isolation rung
[1][12]. Three consequences:
- **Blast radius:** compromise the one signer key → every tenant's grants are forgeable.
- **Metadata co-mingling:** volume, timing, and the pseudonymous relationship graph of
  *all* customers sit on one contract address (the thing you clicked).
- **Bottleneck:** one gas wallet runs dry → everyone's grants stall.

Note what's already **right** and worth keeping: you put **no personal data on chain** —
only `SHA-256(file_id)` and `HMAC(party_id, secret salt)`. That's the correct posture
and the foundation of the GDPR story below. Keep it.

---

## SaaS tier — recommendation

| Lever | Do this | Why |
|-------|---------|-----|
| **Isolation** | **Per-tenant contract via a factory** — each org gets its own contract address | Kills the co-mingled page; per-tenant accountability; a bug in one doesn't touch others [1][12]. Highest-leverage, lowest-cost change. |
| **Party privacy** | **Per-tenant HMAC salt** (you already HMAC; make the salt per-org) | Makes cross-tenant linkage cryptographically impossible, even by equality-clustering. |
| **Gas** | **Keep platform-sponsored gas** — Xinsere pays, bundled into subscription | Correct SaaS UX: customers never touch crypto. On Polygon mainnet a grant is a fraction of a cent, so eating it is financially trivial [3][10]. |
| **Network** | **Move production to Polygon PoS mainnet** | Amoy is a testnet — resets, weak guarantees, not a durable audit trail. Demo only [9]. |

**Sequencing note on the signer.** Per-tenant *contracts* fix the shared-page problem,
but one platform signer still appears as the `sender` on all of them. Full sender-level
isolation while *still* sponsoring gas is the ERC-4337 path: give each tenant a **smart
account** and pay their gas via a **paymaster** (e.g. Circle's Gas Station / Paymaster,
or a self-run one) [3][10][11]. That's the v2 upgrade — not needed to fix what you saw,
but it's the "proper" end state for SaaS.

---

## Enterprise tier — recommendation (your BYO instinct, confirmed)

For studios and other regulated/security-sensitive buyers, control moves to the customer:

- **Bring-your-own keys.** Integrate their HSM / KMS / MPC — AWS KMS-signed EIP-1559 txns
  is a documented pattern [9]; or Fireblocks / Turnkey if they already run those [2][8].
  **We never hold their signing key.** Many studios already have KMS in place.
- **Bring-your-own gas.** They fund and pay. Predictable and auditable on their side.
- **Bring-your-own chain — the real privacy answer.** For the sensitive ones, run the
  permission ledger on a **permissioned chain** (Hyperledger Fabric or Besu / Quorum) so
  it is **not world-readable at all** — membership-gated, per-channel visibility
  [13][14][18]. We ship the connectors; the ledger lives in their trust boundary.
- **Public anchoring for verifiability without exposure.** Periodically write a
  **Merkle-root checkpoint** of the private ledger to public Polygon — tamper-evident,
  independently verifiable, but the underlying grants never touch a public chain. This is
  the Guardtime-KSI / notarization pattern [17], and it maps to your PRD's "public audit
  tier."
- **Self-hosted** (your PRD Mode 5) lives here.

This is exactly the split your PRD already sketched (Fabric enterprise + Arbitrum/anchor
audit tier). The research doesn't change the plan — it confirms it and names the tools.

---

## The privacy/metadata truth, and the mitigation ladder

A public chain **always** leaks transaction metadata — volume, timing, and a pseudonymous
relationship graph — *even when every payload is hashed*. That's inherent, not a bug
[7.1 in the research]. You climb the ladder as sensitivity rises:

1. **Per-tenant contract** — no shared page (SaaS default).
2. **Per-tenant salt** — no cross-tenant linkage.
3. **Mainnet** — durable, real audit trail.
4. **Batching / time-shifting** — blunt timing analysis (only if a customer asks).
5. **Permissioned chain** — remove public visibility entirely (enterprise).
6. **Public anchoring only** — verifiability without exposure (enterprise).

**GDPR / right-to-erasure** reconciles cleanly because you already keep personal data
off-chain: on-chain is only hashes/commitments, so deleting the off-chain mapping
effectively anonymizes the chain record [7.5]. That's a *sellable* compliance line for
enterprise procurement — lead with it.

---

## Recommended phased roadmap for Xinsere

| Phase | Trigger | Build |
|-------|---------|-------|
| **1 — now** (pre-revenue, cheap) | Before any production customer | Per-tenant contract factory · per-tenant salt · production on Polygon **mainnet** · keep platform-sponsored gas. *Fixes the co-mingling you flagged.* |
| **2** | First enterprise deal | BYO-keys connector (KMS / Fireblocks) · BYO-gas · enterprise RPC endpoint. |
| **3** | First privacy-sensitive whale (a studio) | Permissioned-chain connector (Fabric / Besu) · public Merkle-root anchoring. |
| **4** | Scale / UX polish | ERC-4337 paymaster + per-tenant smart accounts → full SaaS sender-isolation with sponsored gas. |

Phase 1 is the only urgent one, and it's small — a factory contract, a per-org salt, and
a mainnet cutover. Everything else is demand-driven and quotable per deal.

---

## Cost note

Don't over-rotate on gas as a cost problem. A grant on Polygon mainnet is a fraction of a
cent; **Xinsere sponsoring gas for the entire SaaS tier is financially trivial at any
plausible early volume**, and it's the correct product decision — a SaaS buyer should
never have to acquire POL. Reserve "customer funds the wallet / pays gas" for the
enterprise tier, where they *want* that control and visibility [3][10].

---

## Sources
[1] Crassula — banking multi-tenancy https://crassula.io/guides/banking-multi-tenancy/ ·
[2] Fireblocks https://www.fireblocks.com/ ·
[3] Circle Programmable Wallets / Gas Station / Paymaster https://developers.circle.com/wallets ·
[4] Coinbase CDP Wallets https://www.coinbase.com/developer-platform/wallets ·
[5] Privy https://www.privy.io/ ·
[6] Magic https://magic.link/ ·
[7] Web3Auth MPC https://web3auth.io/mpc.html ·
[8] Turnkey https://www.turnkey.com/ ·
[9] AWS — signing EIP-1559 txns with KMS https://aws.amazon.com/blogs/database/how-to-sign-ethereum-eip-1559-transactions-using-aws-kms/ ·
[10] ZeroDev — account abstraction https://docs.zerodev.app/blog/what-can-you-do-with-account-abstraction ·
[11] Alchemy — meta-transactions https://www.alchemy.com/overviews/meta-transactions ·
[12] WorkOS — tenant isolation https://workos.com/blog/tenant-isolation-in-multi-tenant-systems ·
[13] GoQuorum https://goquorum.readthedocs.io/ ·
[14] Hyperledger Besu permissioning https://docs.besu-eth.org/private-networks/tutorials/permissioning ·
[15] VeChain ToolChain https://vechaininsider.com/partnerships/a-complete-list-of-vechain-partnerships/ ·
[16] Chainstack — self-hosted nodes https://chainstack.com/self-hosted-blockchain-node-challenges-solutions/ ·
[17] Guardtime KSI (PNNL) https://www.pnnl.gov/main/publications/external/technical_reports/PNNL-27453.pdf ·
[18] Walmart / IBM Food Trust (Hyperledger Fabric) https://www.lfdecentralizedtrust.org/case-studies/walmart-case-study
