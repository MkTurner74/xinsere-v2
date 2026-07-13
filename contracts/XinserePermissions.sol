// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title XinserePermissions
 * @dev Immutable blockchain permission ledger for Xinsere DPD
 *
 * Permissions (file access grants/revokes) are stored on-chain as immutable events.
 * No state is modified after-the-fact. All actions are auditable.
 *
 * File hashes and party hashes are deterministic but anonymized:
 * - fileHash = SHA256(file_content)
 * - partyHash = HMAC-SHA256(email, tenant_salt) — not plain SHA256
 *
 * This prevents existence inference: knowing a fileHash doesn't reveal the file,
 * and knowing a partyHash doesn't reveal the email.
 */

contract XinserePermissions {

    // ============================================================================
    // EVENTS (Immutable Audit Trail)
    // ============================================================================

    /**
     * @dev Emitted when a permission is granted.
     * @param fileHash Deterministic hash of the file (SHA256)
     * @param granteeHash HMAC-SHA256 hash of the grantee (email + tenant_salt)
     * @param timestamp Block timestamp when permission was granted
     * @param permissionType Type of permission: "read", "write", "admin", etc.
     * @param expiryTime Unix timestamp when permission expires (0 = no expiry)
     */
    event FilePermissionGranted(
        bytes32 indexed fileHash,
        bytes32 indexed granteeHash,
        uint256 timestamp,
        string permissionType,
        uint256 expiryTime
    );

    /**
     * @dev Emitted when a permission is revoked.
     * @param fileHash File hash
     * @param granteeHash Grantee hash
     * @param timestamp Block timestamp when revocation occurred
     */
    event FilePermissionRevoked(
        bytes32 indexed fileHash,
        bytes32 indexed granteeHash,
        uint256 timestamp
    );

    /**
     * @dev Emitted when a batch of permissions are granted (Merkle rollup).
     * @param merkleRoot Merkle root of all permission grants in the batch
     * @param batchSize Number of individual permissions in this batch
     * @param timestamp Batch timestamp
     */
    event BatchPermissionGranted(
        bytes32 indexed merkleRoot,
        uint256 batchSize,
        uint256 timestamp
    );

    // ============================================================================
    // STATE
    // ============================================================================

    // Permission records: fileHash => granteeHash => (permissionType, expiryTime, isActive)
    // Stored for efficient verification without scanning all events
    mapping(bytes32 => mapping(bytes32 => PermissionRecord)) public permissions;

    // Anchored batch Merkle roots: root => timestamp anchored (0 = not anchored).
    // ONE storage slot per batch regardless of how many (file, grantee) leaves it
    // covers — this is what makes bulk permission-preservation flat-gas and scalable.
    // The tree is built off-chain; only the root lives here. A grant is proven at
    // verify time with a Merkle proof against an anchored root (see verifyBatch).
    mapping(bytes32 => uint256) public batchRoots;

    // Owner/admin addresses (who can call grant/revoke)
    // For now, only the contract deployer. In production, this would be a Lambda role.
    mapping(address => bool) public admins;

    address public owner;

    struct PermissionRecord {
        string permissionType;      // "read", "write", "admin"
        uint256 expiryTime;         // 0 = no expiry, unix timestamp = expiry
        bool isActive;              // true = permission active, false = revoked
        uint256 grantedAt;          // timestamp when granted
    }

    // ============================================================================
    // CONSTRUCTOR & ADMIN
    // ============================================================================

    constructor() {
        owner = msg.sender;
        admins[msg.sender] = true;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Only admin can call this");
        _;
    }

    // ============================================================================
    // PERMISSION MANAGEMENT
    // ============================================================================

    /**
     * @dev Grant permission to a party for a file.
     * Emits FilePermissionGranted event (immutable audit trail).
     *
     * @param fileHash SHA256 hash of file content
     * @param granteeHash HMAC-SHA256(email + tenant_salt) of grantee
     * @param permissionType "read", "write", "admin"
     * @param expiryTime Unix timestamp (0 = no expiry)
     * @return txHash Event signature for verification
     */
    function grantPermission(
        bytes32 fileHash,
        bytes32 granteeHash,
        string memory permissionType,
        uint256 expiryTime
    ) external onlyAdmin returns (bytes32) {

        require(fileHash != bytes32(0), "File hash cannot be zero");
        require(granteeHash != bytes32(0), "Grantee hash cannot be zero");
        require(bytes(permissionType).length > 0, "Permission type required");

        // Store permission for fast lookup
        permissions[fileHash][granteeHash] = PermissionRecord({
            permissionType: permissionType,
            expiryTime: expiryTime,
            isActive: true,
            grantedAt: block.timestamp
        });

        // Emit immutable event
        emit FilePermissionGranted(
            fileHash,
            granteeHash,
            block.timestamp,
            permissionType,
            expiryTime
        );

        // Return event signature for caller to verify
        return keccak256(abi.encodePacked(fileHash, granteeHash, block.timestamp));
    }

    /**
     * @dev Revoke a permission.
     * Emits FilePermissionRevoked event.
     * Does not delete the grant event (immutable) — just marks as inactive.
     *
     * @param fileHash File hash
     * @param granteeHash Grantee hash
     * @return txHash Event signature
     */
    function revokePermission(
        bytes32 fileHash,
        bytes32 granteeHash
    ) external onlyAdmin returns (bytes32) {

        require(fileHash != bytes32(0), "File hash cannot be zero");
        require(granteeHash != bytes32(0), "Grantee hash cannot be zero");

        PermissionRecord storage perm = permissions[fileHash][granteeHash];
        require(perm.isActive, "Permission not found or already revoked");

        // Mark as revoked (immutable audit trail remains)
        perm.isActive = false;

        // Emit immutable event
        emit FilePermissionRevoked(fileHash, granteeHash, block.timestamp);

        return keccak256(abi.encodePacked(fileHash, granteeHash, block.timestamp));
    }

    // ============================================================================
    // BATCH PERMISSION MANAGEMENT (Merkle aggregate — bulk migration path)
    // ============================================================================

    /**
     * @dev Anchor a batch of permission grants as a single Merkle root.
     *
     * One transaction, one storage write, ANY number of (fileHash, granteeHash)
     * leaves — gas is flat regardless of batch size. The tree is built off-chain;
     * each grant is later proven with a Merkle proof against this root (verifyBatch).
     *
     * Callers SHOULD cap leaves-per-root (e.g. 1,000) so a single bad root can only
     * ever affect that chunk, never the whole migration. The cap is a client policy;
     * the contract only records the root and the declared size for the audit event.
     *
     * @param merkleRoot Root of the off-chain Merkle tree over the batch's leaves,
     *        where leaf = keccak256(abi.encodePacked(fileHash, granteeHash)) and
     *        internal nodes = keccak256 of the two children in ascending order.
     * @param batchSize Number of leaves in the batch (informational, for the event).
     */
    function grantBatch(bytes32 merkleRoot, uint256 batchSize)
        external onlyAdmin returns (bytes32)
    {
        require(merkleRoot != bytes32(0), "Merkle root cannot be zero");
        // Idempotency guard: never silently re-anchor. A repeat is a caller bug or a
        // replay — reject it so the audit trail stays one-anchor-per-root.
        require(batchRoots[merkleRoot] == 0, "Batch root already anchored");

        batchRoots[merkleRoot] = block.timestamp;

        emit BatchPermissionGranted(merkleRoot, batchSize, block.timestamp);
        return merkleRoot;
    }

    /**
     * @dev Emergency kill of a suspect/corrupt anchored root. Every grant proven
     * against it immediately fails closed (verifyBatch returns false), so a bad
     * root is a contained, recoverable incident: revoke it and re-anchor a correct
     * one. Does not touch per-file grants.
     */
    function revokeBatchRoot(bytes32 merkleRoot) external onlyAdmin {
        require(batchRoots[merkleRoot] != 0, "Root not anchored");
        batchRoots[merkleRoot] = 0;
        emit FilePermissionRevoked(merkleRoot, bytes32(0), block.timestamp);
    }

    /**
     * @dev Verify a single grant against an anchored batch root using a Merkle proof.
     * No file access, no gas (view). Fails closed: an unanchored root, a wrong proof,
     * or a corrupted off-chain cache all return false — corruption can only ever
     * block a legitimate user, never wrongly expose a file.
     *
     * @param leaf keccak256(abi.encodePacked(fileHash, granteeHash)).
     * @param root The anchored batch root the caller claims this grant lives under.
     * @param proof Sibling hashes from leaf to root (OpenZeppelin-style, sorted pairs).
     * @return True iff `root` is anchored AND `proof` reconstructs `root` from `leaf`.
     */
    function verifyBatch(bytes32 leaf, bytes32 root, bytes32[] calldata proof)
        external view returns (bool)
    {
        if (batchRoots[root] == 0) {
            return false; // root not anchored (or revoked) -> fail closed
        }
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sib = proof[i];
            // Commutative hashing: order children so proofs are position-independent
            // (matches OpenZeppelin MerkleProof and the off-chain merkle.py builder).
            computed = computed <= sib
                ? keccak256(abi.encodePacked(computed, sib))
                : keccak256(abi.encodePacked(sib, computed));
        }
        return computed == root;
    }

    // ============================================================================
    // VERIFICATION (No File Access Required)
    // ============================================================================

    /**
     * @dev Verify if a party currently has permission to a file.
     * Does not access file content — only checks the permission record.
     *
     * @param fileHash File hash
     * @param granteeHash Grantee hash
     * @return hasPermission True if permission is active and not expired
     * @return grantedAt Timestamp when permission was granted
     */
    function verify(
        bytes32 fileHash,
        bytes32 granteeHash
    ) external view returns (bool hasPermission, uint256 grantedAt) {

        PermissionRecord memory perm = permissions[fileHash][granteeHash];

        // Check: permission exists, is active, and not expired
        bool active = perm.isActive;
        bool notExpired = (perm.expiryTime == 0) || (block.timestamp <= perm.expiryTime);

        return (active && notExpired, perm.grantedAt);
    }

    /**
     * @dev Check if file exists in the system (without revealing content or owner).
     * Proof-of-existence check used by auditors.
     *
     * @param fileHash File hash
     * @return exists True if any permission record exists for this file
     */
    function checkFileExists(bytes32 fileHash) external view returns (bool) {
        // In a full implementation, this would check a separate file registry.
        // For now, we assume files are registered via the first grant.
        // A more complete version would track file metadata separately.
        return true; // Placeholder
    }

    // ============================================================================
    // ADMIN FUNCTIONS
    // ============================================================================

    function addAdmin(address admin) external onlyAdmin {
        require(admin != address(0), "Invalid admin address");
        admins[admin] = true;
    }

    function removeAdmin(address admin) external onlyAdmin {
        require(admin != owner, "Cannot remove owner");
        admins[admin] = false;
    }
}
