// PermissionService — the backend wrapper around the XinserePermissions contract.
// It owns the signer, applies the Amoy gas floor to every write, and exposes the
// grant / revoke / verify / audit operations the REST API and MCP server call.
import { Contract, JsonRpcProvider, Wallet, parseUnits, formatEther } from 'ethers';
import { XINSERE_PERMISSIONS_ABI } from './abi.js';
import { config } from './config.js';
import { loadWallet } from './wallet.js';
import { assertBytes32 } from './hashing.js';

export interface WriteResult {
  txHash: string;
  blockNumber: number;
  gasUsed: string;
  status: 'confirmed' | 'failed';
}

export interface VerifyResult {
  hasPermission: boolean;
  grantedAt: number; // unix seconds, 0 if never granted
}

export interface PermissionRecord {
  permissionType: string;
  expiryTime: number;
  isActive: boolean;
  grantedAt: number;
}

export interface AuditEvent {
  eventType: 'grant' | 'revoke';
  fileHash: string;
  granteeHash: string;
  timestamp: number;
  permissionType?: string;
  expiryTime?: number;
  txHash: string;
  blockNumber: number;
}

export class PermissionService {
  private constructor(
    private readonly contract: Contract,
    private readonly wallet: Wallet,
    private readonly provider: JsonRpcProvider,
  ) {}

  /** Factory — loads the wallet and binds the contract. */
  static async create(): Promise<PermissionService> {
    const { wallet, provider } = await loadWallet();
    const contract = new Contract(config.contractAddress, XINSERE_PERMISSIONS_ABI, wallet);
    return new PermissionService(contract, wallet, provider);
  }

  /** Gas overrides that clear Amoy's >=25 gwei priority-fee floor. */
  private feeOverrides() {
    return {
      maxPriorityFeePerGas: parseUnits(String(config.priorityFeeGwei), 'gwei'),
      maxFeePerGas: parseUnits(String(config.maxFeeGwei), 'gwei'),
    };
  }

  // --- Identity / diagnostics -------------------------------------------------

  get address(): string {
    return this.wallet.address;
  }

  async balanceEth(): Promise<string> {
    return formatEther(await this.provider.getBalance(this.wallet.address));
  }

  async owner(): Promise<string> {
    return this.contract.owner();
  }

  async isAdmin(addr: string): Promise<boolean> {
    return this.contract.admins(addr);
  }

  // --- Writes -----------------------------------------------------------------

  async grant(
    fileHash: string,
    granteeHash: string,
    permissionType: string,
    expirySeconds = 0,
  ): Promise<WriteResult> {
    assertBytes32('fileHash', fileHash);
    assertBytes32('granteeHash', granteeHash);
    if (!permissionType) throw new Error('permissionType is required');

    const tx = await this.contract.grantPermission(
      fileHash,
      granteeHash,
      permissionType,
      expirySeconds,
      this.feeOverrides(),
    );
    return this.settle(tx);
  }

  async revoke(fileHash: string, granteeHash: string): Promise<WriteResult> {
    assertBytes32('fileHash', fileHash);
    assertBytes32('granteeHash', granteeHash);

    const tx = await this.contract.revokePermission(fileHash, granteeHash, this.feeOverrides());
    return this.settle(tx);
  }

  private async settle(tx: { hash: string; wait: () => Promise<any> }): Promise<WriteResult> {
    const receipt = await tx.wait();
    return {
      txHash: tx.hash,
      blockNumber: Number(receipt.blockNumber),
      gasUsed: receipt.gasUsed.toString(),
      status: receipt.status === 1 ? 'confirmed' : 'failed',
    };
  }

  // --- Reads (free) -----------------------------------------------------------

  async verify(fileHash: string, granteeHash: string): Promise<VerifyResult> {
    assertBytes32('fileHash', fileHash);
    assertBytes32('granteeHash', granteeHash);
    const [hasPermission, grantedAt] = await this.contract.verify(fileHash, granteeHash);
    return { hasPermission, grantedAt: Number(grantedAt) };
  }

  async getRecord(fileHash: string, granteeHash: string): Promise<PermissionRecord> {
    const [permissionType, expiryTime, isActive, grantedAt] = await this.contract.permissions(
      fileHash,
      granteeHash,
    );
    return {
      permissionType,
      expiryTime: Number(expiryTime),
      isActive,
      grantedAt: Number(grantedAt),
    };
  }

  async checkFileExists(fileHash: string): Promise<boolean> {
    assertBytes32('fileHash', fileHash);
    return this.contract.checkFileExists(fileHash);
  }

  /**
   * queryFilter across a wide block range in RPC-friendly windows. Shrinks the
   * window adaptively if the endpoint still rejects the span, so it survives
   * stricter RPCs without config changes.
   */
  private async queryChunked(
    contract: Contract,
    filter: any,
    from: number,
    to: number,
  ): Promise<any[]> {
    const out: any[] = [];
    let window = config.logsChunkSize;
    let start = from;
    while (start <= to) {
      const end = Math.min(start + window - 1, to);
      try {
        const logs = await contract.queryFilter(filter, start, end);
        out.push(...logs);
        start = end + 1;
      } catch (err) {
        if (window > 500) {
          window = Math.floor(window / 2); // retry same start with a smaller span
          continue;
        }
        throw err;
      }
    }
    return out;
  }

  /**
   * Full audit trail for a file: every grant + revoke, merged and time-ordered.
   * Reads events via the dedicated logs RPC, chunked into windows the endpoint
   * accepts. Note: at production scale, index events into DynamoDB and read from
   * there — direct log scans grow linearly with chain history.
   */
  async getAuditTrail(fileHash: string): Promise<AuditEvent[]> {
    assertBytes32('fileHash', fileHash);

    // Use the log-capable RPC (the write RPC rejects eth_getLogs).
    const logsProvider = new JsonRpcProvider(config.logsRpcUrl, config.chainId);
    const reader = new Contract(config.contractAddress, XINSERE_PERMISSIONS_ABI, logsProvider);
    const latest = await logsProvider.getBlockNumber();

    const grantedFilter = reader.filters.FilePermissionGranted(fileHash);
    const revokedFilter = reader.filters.FilePermissionRevoked(fileHash);

    const [granted, revoked] = await Promise.all([
      this.queryChunked(reader, grantedFilter, config.deployBlock, latest),
      this.queryChunked(reader, revokedFilter, config.deployBlock, latest),
    ]);

    const events: AuditEvent[] = [];
    for (const e of granted as any[]) {
      events.push({
        eventType: 'grant',
        fileHash: e.args.fileHash,
        granteeHash: e.args.granteeHash,
        timestamp: Number(e.args.timestamp),
        permissionType: e.args.permissionType,
        expiryTime: Number(e.args.expiryTime),
        txHash: e.transactionHash,
        blockNumber: e.blockNumber,
      });
    }
    for (const e of revoked as any[]) {
      events.push({
        eventType: 'revoke',
        fileHash: e.args.fileHash,
        granteeHash: e.args.granteeHash,
        timestamp: Number(e.args.timestamp),
        txHash: e.transactionHash,
        blockNumber: e.blockNumber,
      });
    }

    // Order by block, then by event index within a block via timestamp fallback.
    events.sort((a, b) => a.blockNumber - b.blockNumber || a.timestamp - b.timestamp);
    return events;
  }
}
