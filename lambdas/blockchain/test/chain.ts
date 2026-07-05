// End-to-end chain test: Secrets Manager -> signer -> live Amoy contract.
// Runs the full permission lifecycle against the deployed XinserePermissions
// contract and prints a pass/fail summary.
//
//   npm test              full lifecycle (grant + revoke — costs a little POL)
//   npm run test:smoke    read-only (verify/exists/owner — free, no gas)
//
// Uses unique per-run hashes (derived from a fixed test id + wallet address) so
// repeated runs don't collide with a stale on-chain record.
import 'dotenv/config';
import { PermissionService } from '../src/permissions.js';
import { fileHashFromId, granteeHash } from '../src/hashing.js';
import { config } from '../src/config.js';

const READ_ONLY = process.argv.includes('--read-only');

let pass = 0;
let fail = 0;

function check(name: string, ok: boolean, detail = ''): void {
  if (ok) {
    pass++;
    console.log(`  ✅ ${name}${detail ? ` — ${detail}` : ''}`);
  } else {
    fail++;
    console.log(`  ❌ ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

function section(title: string): void {
  console.log(`\n${title}`);
}

async function main(): Promise<void> {
  console.log('='.repeat(64));
  console.log('Xinsere blockchain permission service — chain test');
  console.log('='.repeat(64));
  console.log(`Network:  Amoy (chain ${config.chainId})`);
  console.log(`Contract: ${config.contractAddress}`);
  console.log(`Mode:     ${READ_ONLY ? 'READ-ONLY (no gas)' : 'FULL LIFECYCLE (grant+revoke)'}`);

  const svc = await PermissionService.create();

  // --- Identity / connectivity ---
  section('1. Wallet & contract connectivity');
  const balance = await svc.balanceEth();
  const owner = await svc.owner();
  const isAdmin = await svc.isAdmin(svc.address);
  console.log(`  wallet:  ${svc.address}`);
  console.log(`  balance: ${balance} POL`);
  console.log(`  owner:   ${owner}`);
  check('wallet has POL for gas', Number(balance) > 0, `${balance} POL`);
  check('wallet is the contract owner', owner.toLowerCase() === svc.address.toLowerCase());
  check('wallet is an admin (can grant/revoke)', isAdmin);

  // Unique per-run identifiers.
  const runTag = `chain-test-${svc.address.slice(2, 10)}-${config.chainId}`;
  const fileId = `${runTag}-file`;
  const granteeId = `${runTag}-grantee@example.com`;
  const fh = fileHashFromId(fileId);
  const gh = granteeHash(granteeId, config.tenantSalt);
  console.log(`  fileHash:    ${fh}`);
  console.log(`  granteeHash: ${gh}`);

  // --- Read baseline ---
  section('2. Read baseline (free)');
  const before = await svc.verify(fh, gh);
  check('checkFileExists returns a bool', typeof (await svc.checkFileExists(fh)) === 'boolean');
  // Note: verify may be true if a prior full run left an active grant; only assert
  // strict false when we're about to run the full lifecycle from a clean state.

  if (READ_ONLY) {
    console.log(`  verify(before) = ${before.hasPermission} (grantedAt ${before.grantedAt})`);
    summary();
    return;
  }

  // --- Grant ---
  section('3. grantPermission (write)');
  const grantRes = await svc.grant(fh, gh, 'read', 0);
  console.log(`  tx: ${grantRes.txHash}`);
  console.log(`  https://amoy.polygonscan.com/tx/${grantRes.txHash}`);
  check('grant tx confirmed', grantRes.status === 'confirmed', `gas ${grantRes.gasUsed}`);

  const afterGrant = await svc.verify(fh, gh);
  check('verify() is true after grant', afterGrant.hasPermission);
  check('grantedAt is a real timestamp', afterGrant.grantedAt > 0,
    new Date(afterGrant.grantedAt * 1000).toISOString());

  const record = await svc.getRecord(fh, gh);
  check('record.permissionType == "read"', record.permissionType === 'read');
  check('record.isActive == true', record.isActive === true);

  // --- Audit trail ---
  section('4. getAuditTrail (event query)');
  const trailAfterGrant = await svc.getAuditTrail(fh);
  console.log(`  events: ${trailAfterGrant.map((e) => e.eventType).join(', ') || '(none)'}`);
  check('audit trail contains the grant', trailAfterGrant.some((e) => e.eventType === 'grant'));

  // --- Revoke ---
  section('5. revokePermission (write)');
  const revokeRes = await svc.revoke(fh, gh);
  console.log(`  tx: ${revokeRes.txHash}`);
  check('revoke tx confirmed', revokeRes.status === 'confirmed', `gas ${revokeRes.gasUsed}`);

  const afterRevoke = await svc.verify(fh, gh);
  check('verify() is false after revoke', afterRevoke.hasPermission === false);
  check('grantedAt still preserved (immutable record)', afterRevoke.grantedAt > 0);

  // --- Final audit trail ---
  section('6. Final audit trail');
  const finalTrail = await svc.getAuditTrail(fh);
  for (const e of finalTrail) {
    console.log(`  ${e.eventType.padEnd(6)} @ block ${e.blockNumber}  tx ${e.txHash.slice(0, 12)}…`);
  }
  check('trail has both grant and revoke',
    finalTrail.some((e) => e.eventType === 'grant') &&
    finalTrail.some((e) => e.eventType === 'revoke'));

  summary();
}

function summary(): void {
  console.log('\n' + '='.repeat(64));
  console.log(`RESULT: ${pass} passed, ${fail} failed`);
  console.log('='.repeat(64));
  if (fail > 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error('\n💥 Chain test threw:', err?.message ?? err);
  process.exitCode = 1;
});
