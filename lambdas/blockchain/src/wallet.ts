// Wallet loader. The private key lives in AWS Secrets Manager and is fetched at
// runtime — never stored on disk, never logged. In the Lambda this uses the
// execution role's read-only access to the secret. For local testing you can set
// XINSERE_PRIVATE_KEY as a fallback (dev only).
//
// Security: the key is held in memory only for the life of the signer. It is never
// printed. Errors here are deliberately sanitised so a bad key value can never leak
// into logs or stack traces.
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { Wallet, JsonRpcProvider } from 'ethers';
import { config } from './config.js';

/** Normalise a raw key string to 0x-prefixed 32-byte hex. Never echoes the value. */
function normaliseKey(raw: string): string {
  const k = raw.trim();
  const bare = k.startsWith('0x') ? k.slice(2) : k;
  if (!/^[0-9a-fA-F]{64}$/.test(bare)) {
    throw new Error('Private key is not valid 32-byte hex (value withheld from logs)');
  }
  return '0x' + bare;
}

/**
 * Extract the private key from a secret payload. Handles proper JSON
 * ({"private_key":"0x..."}), a bare key string, and the malformed unquoted form
 * ({private_key:abc...,address:0x...}) that older tooling wrote.
 */
function extractKey(secretString: string): string {
  const s = secretString.trim();

  // 1. Proper JSON.
  try {
    const parsed = JSON.parse(s) as { private_key?: string; privateKey?: string };
    const k = parsed.private_key ?? parsed.privateKey;
    if (k) return normaliseKey(k);
  } catch {
    /* fall through to tolerant parsing */
  }

  // 2. Tolerant: pull a private_key field even if unquoted/malformed.
  const field = s.match(/private_?key["\s:]+\s*"?(0x)?([0-9a-fA-F]{64})/i);
  if (field) return normaliseKey('0x' + field[2]);

  // 3. Bare 64-hex string (optionally 0x-prefixed).
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(s)) return normaliseKey(s);

  throw new Error('Secret does not contain a recognisable private key (value withheld)');
}

async function loadPrivateKey(): Promise<{ key: string; source: string }> {
  // Explicit dev override — only when the operator sets it deliberately.
  if (config.privateKeyOverride) {
    return { key: normaliseKey(config.privateKeyOverride), source: 'env (XINSERE_PRIVATE_KEY)' };
  }

  const client = new SecretsManagerClient({ region: config.awsRegion });
  const res = await client.send(new GetSecretValueCommand({ SecretId: config.secretId }));
  if (!res.SecretString) {
    throw new Error(`Secret ${config.secretId} has no SecretString`);
  }
  return { key: extractKey(res.SecretString), source: 'secrets-manager' };
}

export interface LoadedWallet {
  wallet: Wallet;
  provider: JsonRpcProvider;
  address: string;
  keySource: string;
}

/** Build a provider + signer bound to the configured network. */
export async function loadWallet(): Promise<LoadedWallet> {
  const provider = new JsonRpcProvider(config.rpcUrl, config.chainId);
  const { key, source } = await loadPrivateKey();
  let wallet: Wallet;
  try {
    wallet = new Wallet(key, provider);
  } catch {
    // Never surface the key value in an error.
    throw new Error('Failed to construct wallet from the retrieved key (value withheld)');
  }
  return { wallet, provider, address: wallet.address, keySource: source };
}
