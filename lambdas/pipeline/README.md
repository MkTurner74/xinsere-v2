# Xinsere File-Fragment Pipeline

The store/retrieve half of Xinsere: shred a file into encrypted fragments
scattered across buckets, and put it back together only for an authorized caller.

Implements the improved design from the PRD (§ "Encryption improvements"):
per-**fragment** AES-256-GCM keys, SHA-256 everywhere, `{uuid}_{sequence}`
fragment names, metadata stripped, in-memory only.

## How it works

**Store:** strip metadata → SHA-256 the whole file → split into N fragments →
per fragment: fresh data key + AES-256-GCM encrypt → scatter across buckets →
index `{wrapped_key, nonce, bucket, sequence}`.

**Retrieve:** read fragments by `file_id` → per fragment: unwrap key + decrypt
(authenticated — tamper is detected) → reassemble in order → verify whole-file
SHA-256 → return bytes.

The **wrapped keys and ordering live only in the index**, never with the
fragments — so a stolen bucket yields ciphertext with no keys and no sequence.

## Pluggable backends

The pipeline depends on three interfaces (`backends/base.py`):

| Interface | Local (testing) | Production |
|-----------|-----------------|------------|
| `KeyManager` | `LocalKeyManager` — AES-GCM under a master key | `KmsKeyManager` — AWS KMS `GenerateDataKey`/`Decrypt` |
| `ObjectStore` | `LocalObjectStore` — dirs/memory as buckets | `S3ObjectStore` — multi-bucket S3 |
| `IndexStore` | `LocalIndexStore` — in-memory | `DynamoIndexStore` — DynamoDB |

The full pipeline + test matrix run offline against the local backends today.
Swapping in the AWS backends (once P0 infra exists — S3 buckets, KMS CMK,
DynamoDB tables) is a construction-time config change, no pipeline edits.

## Run the test matrix

```bash
cd lambdas/pipeline
pip install -r requirements.txt   # cryptography (boto3 only for AWS backends)
python tests/test_matrix.py
```

Covers round-trip correctness (all sizes + fragment counts 3/5/7/11/16),
security (no plaintext leakage, tamper detection, missing-fragment, wrong-key,
metadata stripping), distribution, and lifecycle. Current status: **18/18 pass.**

## Usage

```python
from xinsere_pipeline import PipelineService
from xinsere_pipeline.backends.local import LocalObjectStore, LocalKeyManager, LocalIndexStore

svc = PipelineService(LocalObjectStore(), LocalKeyManager(), LocalIndexStore(), fragment_count=7)
res = svc.store(content_bytes, "application/pdf", label="optional")
out = svc.retrieve(res.file_id)          # -> RetrieveResult(content, content_type, file_sha256)
```

## Notes / future work

- **Permissions are separate.** This layer is storage only; enforce a blockchain
  permission check (the `lambdas/blockchain` service) in front of `retrieve()` at
  the API layer.
- **Contiguous split.** Fragments are contiguous byte ranges, each encrypted, so
  no stored fragment is readable. Byte-striping is a possible future hardening.
- **Hybrid mode** (odd→customer, even→Xinsere buckets) is implemented in the
  router; wiring per-operator credentials is a deployment concern.
