// Centralised config for the blockchain permission service.
// Values come from the environment with Amoy-correct defaults, so the service
// runs with zero config in the deployed Lambda and reads .env locally.

function num(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (Number.isNaN(n)) throw new Error(`Env ${name} must be a number, got "${raw}"`);
  return n;
}

export const config = {
  rpcUrl: process.env.XINSERE_RPC_URL ?? 'https://rpc-amoy.polygon.technology',
  chainId: num('XINSERE_CHAIN_ID', 80002),
  contractAddress:
    process.env.XINSERE_CONTRACT_ADDRESS ?? '0xf2978c58Ec46103FC2110575DFd62cf3ba997FCD',

  // Separate RPC for event/log queries. The default write RPC
  // (rpc-amoy.polygon.technology) rejects eth_getLogs for any range; drpc.org
  // serves filtered logs in <=10k-block windows. Kept distinct so tx submission
  // stays on the official endpoint.
  logsRpcUrl: process.env.XINSERE_LOGS_RPC_URL ?? 'https://polygon-amoy.drpc.org',
  logsChunkSize: num('XINSERE_LOGS_CHUNK_SIZE', 9000),

  // Anchor for audit-trail scans — a block at/just before contract deployment
  // (2026-07-03). Fixed so no events are missed; scan chunks forward from here.
  deployBlock: num('XINSERE_DEPLOY_BLOCK', 41330000),

  // Wallet
  secretId: process.env.XINSERE_SECRET_ID ?? 'xinsere/blockchain/polygon-mumbai/private-key',
  awsRegion: process.env.AWS_REGION ?? 'us-east-1',
  privateKeyOverride: process.env.XINSERE_PRIVATE_KEY, // dev-only fallback

  // Grantee hashing
  tenantSalt: process.env.XINSERE_TENANT_SALT ?? 'dev-tenant-salt-change-me',

  // Gas — Amoy rejects priority fees below 25 gwei ("gas price below minimum").
  priorityFeeGwei: num('XINSERE_PRIORITY_FEE_GWEI', 30),
  maxFeeGwei: num('XINSERE_MAX_FEE_GWEI', 50),
} as const;

export type XinsereConfig = typeof config;
