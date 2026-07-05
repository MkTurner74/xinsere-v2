// Lambda entry point for the blockchain permission service.
// Action-routed so it can sit behind API Gateway or be invoked directly by the
// file-pipeline Lambdas. Hashing happens here so callers pass opaque ids, not
// on-chain hashes — the service never sees a raw file or plaintext identity.
//
// Event shape:
//   { action: "grant", fileId, granteeId, permissionType, expirySeconds? }
//   { action: "revoke", fileId, granteeId }
//   { action: "verify", fileId, granteeId }
//   { action: "audit", fileId }
//   { action: "exists", fileId }
//
// The service is created once per container and reused across invocations.
import { PermissionService } from './permissions.js';
import { fileHashFromId, granteeHash } from './hashing.js';
import { config } from './config.js';

let servicePromise: Promise<PermissionService> | null = null;
function getService(): Promise<PermissionService> {
  if (!servicePromise) servicePromise = PermissionService.create();
  return servicePromise;
}

interface ActionEvent {
  action: string;
  fileId?: string;
  granteeId?: string;
  permissionType?: string;
  expirySeconds?: number;
}

export async function handler(event: ActionEvent): Promise<unknown> {
  const svc = await getService();
  const fh = event.fileId ? fileHashFromId(event.fileId) : undefined;
  const gh = event.granteeId ? granteeHash(event.granteeId, config.tenantSalt) : undefined;

  switch (event.action) {
    case 'grant':
      requireAll(event, ['fileId', 'granteeId', 'permissionType']);
      return svc.grant(fh!, gh!, event.permissionType!, event.expirySeconds ?? 0);

    case 'revoke':
      requireAll(event, ['fileId', 'granteeId']);
      return svc.revoke(fh!, gh!);

    case 'verify':
      requireAll(event, ['fileId', 'granteeId']);
      return svc.verify(fh!, gh!);

    case 'audit':
      requireAll(event, ['fileId']);
      return svc.getAuditTrail(fh!);

    case 'exists':
      requireAll(event, ['fileId']);
      return { exists: await svc.checkFileExists(fh!) };

    default:
      throw new Error(`Unknown action "${event.action}"`);
  }
}

function requireAll(event: ActionEvent, keys: (keyof ActionEvent)[]): void {
  const missing = keys.filter((k) => event[k] === undefined || event[k] === '');
  if (missing.length) throw new Error(`Missing required field(s): ${missing.join(', ')}`);
}
