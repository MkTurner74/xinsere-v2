// ABI for the XinserePermissions contract (mirrors contracts/abi.json).
// Only the members the service calls are included — grant/revoke/verify,
// the two permission events, and the owner/admin/permissions getters.
export const XINSERE_PERMISSIONS_ABI = [
  'function grantPermission(bytes32 fileHash, bytes32 granteeHash, string permissionType, uint256 expiryTime) returns (bytes32)',
  'function revokePermission(bytes32 fileHash, bytes32 granteeHash) returns (bytes32)',
  'function verify(bytes32 fileHash, bytes32 granteeHash) view returns (bool hasPermission, uint256 grantedAt)',
  'function checkFileExists(bytes32 fileHash) view returns (bool)',
  'function permissions(bytes32, bytes32) view returns (string permissionType, uint256 expiryTime, bool isActive, uint256 grantedAt)',
  'function owner() view returns (address)',
  'function admins(address) view returns (bool)',
  'function addAdmin(address admin)',
  'function removeAdmin(address admin)',
  'event FilePermissionGranted(bytes32 indexed fileHash, bytes32 indexed granteeHash, uint256 timestamp, string permissionType, uint256 expiryTime)',
  'event FilePermissionRevoked(bytes32 indexed fileHash, bytes32 indexed granteeHash, uint256 timestamp)',
] as const;
