// Hashing helpers that turn opaque identifiers into the bytes32 values the
// contract stores. These match the scheme documented in XinserePermissions.sol:
//
//   fileHash    = SHA-256(file_content)           — deterministic, reveals nothing
//   granteeHash = HMAC-SHA256(identity, salt)     — per-tenant salt blocks inference
//
// Everything on-chain is a hash: knowing a fileHash doesn't reveal the file, and
// knowing a granteeHash doesn't reveal the identity behind it.
import { createHash, createHmac } from 'node:crypto';

const BYTES32 = /^0x[0-9a-fA-F]{64}$/;

/** SHA-256 of raw bytes → 0x-prefixed bytes32. Use on file content. */
export function fileHashFromContent(content: Uint8Array | Buffer): string {
  return '0x' + createHash('sha256').update(content).digest('hex');
}

/** SHA-256 of a string (e.g. an opaque file_id) → bytes32. */
export function fileHashFromId(fileId: string): string {
  return '0x' + createHash('sha256').update(fileId, 'utf8').digest('hex');
}

/** HMAC-SHA256(identity, tenantSalt) → bytes32. Use on grantee/party identity. */
export function granteeHash(identity: string, tenantSalt: string): string {
  return '0x' + createHmac('sha256', tenantSalt).update(identity, 'utf8').digest('hex');
}

/** Guard: throw if a value isn't a well-formed non-zero bytes32. */
export function assertBytes32(label: string, value: string): void {
  if (!BYTES32.test(value)) {
    throw new Error(`${label} must be a 0x-prefixed 32-byte hex string, got "${value}"`);
  }
  if (/^0x0{64}$/.test(value)) {
    throw new Error(`${label} cannot be the zero hash (contract rejects it)`);
  }
}
