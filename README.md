# PQC EnFram Zero

Post-Quantum Cryptography Encryption Framework for Zero Trust Security is a client-side encryption library for AWS DynamoDB integrating **ML-KEM** (CRYSTALS-Kyber) and **ML-DSA** (CRYSTALS-Dilithium).

## Overview

PQC EnFram Zero adapts [CryptDB](https://css.csail.mit.edu/cryptdb/)'s onion encryption architecture for NoSQL key-value stores. All data is decrypted only on the client — DynamoDB stores exclusively ciphertext. The framework is transparent to callers: `put`/`get`/`delete` work like any KV store, encryption happens automatically.

### Security Principles

1. **Client-only plaintext** — no plaintext ever leaves the JVM process
2. **ML-KEM for data-in-transit** — a fresh ephemeral ML-KEM-1024 shared secret is encapsulated per write and stored alongside the ciphertext; transit key confidentiality is quantum-resistant
3. **AES-256-GCM for data-at-rest** — symmetric encryption with a random IV per write; same value written twice produces different ciphertext
4. **ML-DSA integrity** — every stored item is signed with ML-DSA-65; tampering is detected before decryption
5. **Encrypted queries** — DynamoDB partition keys are HMAC-SHA256 derivations of the plaintext key; key content is never exposed to the server

---

## Main Operations Architecture

### `put(key, value)`

| Step | Layer | Operation | Output |
|------|-------|-----------|--------|
| 1 | At-rest | `AES-GCM(DEK, value)` | `encryptedValue` |
| 2 | Key derivation | `HMAC-SHA256(DEK, key)` | `deterministicKey` — stored as DynamoDB `pk` |
| 3 | Assembly | `serialise(deterministicKey, encryptedValue)` | `payload` |
| 4 | Transit | `ML-KEM.encapsulate(kemPublicKey)` — fresh per call | `transitKey` + `encapsulation` |
| 5 | Transit | `AES-GCM(transitKey, payload)` | `encryptedPayload` |
| 6 | Integrity | `ML-DSA.sign(encapsulation ‖ encryptedPayload)` | `signature` |
| 7 | Storage | `DynamoDB.put(pk, kem, payload, sig)` | — |

### `get(key)`

| Step | Layer | Operation | Output |
|------|-------|-----------|--------|
| 1 | Key derivation | `HMAC-SHA256(DEK, key)` | `deterministicKey` |
| 2 | Fetch | `DynamoDB.get(deterministicKey)` | envelope |
| 3 | Integrity | `ML-DSA.verify(sig, encapsulation ‖ payload)` | throws `IntegrityException` if invalid |
| 4 | Transit | `ML-KEM.decapsulate(kemPrivKey, encapsulation)` | `transitKey` |
| 5 | Transit | `AES-GCM.decrypt(transitKey, encryptedPayload)` | `payload` |
| 6 | At-rest | `AES-GCM.decrypt(DEK, encryptedValue)` | plaintext value (JVM memory only) |

## Project Structure

```
pqc-enfram-zero/
├── pom.xml
├── infra/
│   ├── main.tf
│   ├── variables.tf
│   └── outputs.tf
└── src/
    ├── main/java/org/pqc/enframzero/
    │   ├── crypto/
    │   │   ├── AesGcmService.java
    │   │   ├── AesGcmServiceImpl.java
    │   │   ├── MlKemService.java
    │   │   ├── MlKemServiceImpl.java
    │   │   ├── MlDsaService.java
    │   │   ├── MlDsaServiceImpl.java
    │   │   ├── CryptoConstants.java
    │   │   └── CryptoException.java
    │   ├── keys/
    │   │   ├── PqcKeyBundle.java
    │   │   ├── PqcKeyManager.java
    │   │   ├── InMemoryKeyManager.java
    │   │   ├── KeyBundleRegistry.java
    │   │   ├── KeyBundleSerializer.java
    │   │   └── KmsBlobKeyStore.java
    │   ├── onion/
    │   │   ├── OnionLayer.java
    │   │   ├── KeyOnion.java
    │   │   ├── ValueOnion.java
    │   │   └── TransitEnvelope.java
    │   ├── store/
    │   │   ├── EncryptedStore.java
    │   │   └── DynamoDbEncryptedStore.java
    │   └── framework/
    │       ├── PqcFramework.java
    │       ├── PqcFrameworkImpl.java
    │       └── IntegrityException.java
    └── test/java/org/pqc/enframzero/
        ├── benchmark/
        │   ├── BenchmarkSuite.java
        │   ├── CloudBenchmarkSuite.java
        │   └── InMemoryEncryptedStore.java
        ├── crypto/
        │   ├── AesGcmServiceImplTest.java
        │   ├── MlKemServiceImplTest.java
        │   └── MlDsaServiceImplTest.java
        ├── keys/
        │   ├── KeyBundleSerializerTest.java
        │   └── KmsBlobKeyStoreIntegrationTest.java
        ├── onion/
        │   ├── KeyOnionTest.java
        │   ├── ValueOnionTest.java
        │   └── TransitEnvelopeTest.java
        ├── framework/
        │   └── PqcFrameworkRoundTripTest.java
        └── store/
            └── DynamoDbEncryptedStoreIntegrationTest.java
```

## Framework Modules

### `org.pqc.enframzero.crypto`

- **AesGcmService.java** — Interface: `encrypt(plaintext, key)` / `decrypt(ivAndCiphertext, key)`
- **AesGcmServiceImpl.java** — AES/GCM/NoPadding with a fresh 12-byte random IV per call; output is `IV ‖ ciphertext ‖ 128-bit tag`
- **MlKemService.java** — Interface: `encapsulate(publicKey) → KemResult` / `decapsulate(privateKey, encapsulation) → sharedSecret`
- **MlKemServiceImpl.java** — ML-KEM-1024 via Bouncy Castle `MLKEMGenerator` / `MLKEMExtractor`
- **MlDsaService.java** — Interface: `sign(message, privateKey) → signature` / `verify(message, signature, publicKey) → boolean`
- **MlDsaServiceImpl.java** — ML-DSA-65 via Bouncy Castle `MLDSASigner`
- **CryptoConstants.java** — Shared constants: `AES_GCM_IV_BYTES = 12`, `AES_GCM_TAG_BITS = 128`, `AES_KEY_BYTES = 32`
- **CryptoException.java** — Unchecked wrapper for cryptographic failures

### `org.pqc.enframzero.keys`

- **PqcKeyBundle.java** — `AutoCloseable` container holding the ML-KEM-1024 keypair, ML-DSA-65 keypair, and 32-byte AES-256 DEK; `destroy()` zeroes the DEK bytes in-place
- **PqcKeyManager.java** — Interface: `generateKeys() → PqcKeyBundle`
- **InMemoryKeyManager.java** — Generates ML-KEM-1024 + ML-DSA-65 keypairs and a random AES-256 DEK; all key material lives only in JVM heap, never written to disk
- **KeyBundleRegistry.java** — Thread-safe named registry of `PqcKeyBundle` instances; always contains a `"master"` bundle; `getOrCreate(id)` auto-generates a new bundle if the id is not yet registered; callers are responsible for persisting auto-generated bundles via `KmsBlobKeyStore`
- **KeyBundleSerializer.java** — Serialises all five key components to a compact binary format (`[4-byte length][bytes]` per field); used internally by `KmsBlobKeyStore`
- **KmsBlobKeyStore.java** — Persists a `PqcKeyBundle` across JVM restarts using KMS envelope encryption: `GenerateDataKey` → AES-GCM encrypt the serialised bundle → write blob to file; on load: `Decrypt` the envelope DEK → AES-GCM decrypt → deserialise

### `org.pqc.enframzero.onion`

- **OnionLayer.java** — Enum with three levels: `PLAIN` (no transformation), `DET` (deterministic — same input always produces the same output), `RND` (randomised — fresh IV per call)
- **KeyOnion.java** — Transforms plaintext keys per layer: `DET` = `HMAC-SHA256(DEK, key)` encoded as Base64URL; `RND` = `AES-GCM(DEK, key)`; `PLAIN` = passthrough
- **ValueOnion.java** — At-rest encryption layer: `AES-GCM(DEK, value)` with a fresh 12-byte random IV per write; same value written twice always produces different ciphertext
- **TransitEnvelope.java** — Immutable record carrying `keyId`, `kemEncapsulation`, `encryptedPayload`, and `dsaSignature`; `keyId` identifies which bundle encrypted the row; inner payload is serialised as `[4-byte length][deterministicKey][encryptedValue]`

### `org.pqc.enframzero.store`

- **EncryptedStore.java** — Interface: `put(deterministicKey, TransitEnvelope)` / `get(deterministicKey) → Optional<TransitEnvelope>` / `delete(deterministicKey)`; implement this to target any KV backend
- **DynamoDbEncryptedStore.java** — AWS DynamoDB implementation: maps `TransitEnvelope` fields to Binary attributes (`pk`, `kid`, `kem`, `payload`, `sig`) and back using AWS SDK v2 `DynamoDbClient`; rows without a `kid` attribute (written before multi-bundle support) default to `"master"`

### `org.pqc.enframzero.framework`

- **PqcFramework.java** — Public API interface: no-arg `put`/`get`/`delete` use the master bundle; `put(key, value, bundleId)` / `get(key, bundleId)` / `delete(key, bundleId)` overloads use a named bundle (auto-created if missing on `put`); default `putString` / `getString` convenience overloads (UTF-8) in both forms
- **PqcFrameworkImpl.java** — Wires all modules together and orchestrates the full encryption/decryption flow; `create(table, region)` generates a fresh master bundle; `create(table, region, bundle)` accepts an existing `PqcKeyBundle`; `create(table, region, registry)` accepts a pre-populated `KeyBundleRegistry`
- **IntegrityException.java** — Unchecked exception thrown by `get()` when ML-DSA signature verification fails, indicating the stored envelope was tampered with

## Requirements

- **Java**: `jdk21+`
- **Maven**: `3.8+`
- AWS credentials configured (`~/.aws/credentials` or as `ENV`)

### Optional

- Terraform 1.x (only for infrastructure deployment - see [infra/](infra/))

## Tests

| Test class | Type | Count | What it covers |
|---|---|---|---|
| `crypto/AesGcmServiceImplTest` | Unit | 6 | Round-trip, random IV, tamper detection, wrong key |
| `crypto/MlKemServiceImplTest` | Unit | 5 | Encapsulate/decapsulate, ephemeral keys, shared secret size |
| `crypto/MlDsaServiceImplTest` | Unit | 5 | Sign/verify, tampered message/signature, wrong public key |
| `keys/KeyBundleSerializerTest` | Unit | 4 | Round-trip preserves all key components, size bounds, different bundles, works with framework |
| `onion/KeyOnionTest` | Unit | 6 | DET determinism, RND randomness, Base64URL encoding |
| `onion/ValueOnionTest` | Unit | 3 | Round-trip, random ciphertext per write |
| `onion/TransitEnvelopeTest` | Unit | 3 | Serialise/deserialise, signInput concatenation |
| `framework/PqcFrameworkRoundTripTest` | Unit | 14 | put/get, overwrite, delete, multi-key, integrity check, multi-bundle round-trip, auto-creation, cross-bundle isolation |
| `keys/KmsBlobKeyStoreIntegrationTest` | Integration | 2 | Save/load round-trip via KMS, cross-restart read of existing DynamoDB data |
| `store/DynamoDbEncryptedStoreIntegrationTest` | Integration | 1 | put/get/delete against a live DynamoDB table |
| `benchmark/BenchmarkSuite` | Benchmark | 1 | Primitive latency (ML-KEM, ML-DSA, AES-GCM, HMAC), classical comparison (ECDH-P256, ECDSA-P256), in-memory framework put/get, storage overhead |
| `benchmark/CloudBenchmarkSuite` | Benchmark | 1 | Key management overhead, AWS KMS call latency, real DynamoDB put/get with full network round-trip |

**46 unit tests** — no AWS infrastructure required.
**3 integration tests** — tagged `@Tag("integration")` and excluded by default.
**2 benchmark suites** — tagged `@Tag("benchmark")` / `@Tag("cloud-benchmark")` and excluded by default.

## Build & Test

**Compile**
```bash
mvn compile
```

**Unit tests**
```bash
mvn test
```

**Integration tests** — requires deployed DynamoDB + KMS
```bash
PQC_TABLE_NAME=pqc-items-dev PQC_KMS_KEY_ALIAS=alias/pqc-keystore-dev \
  mvn test -Dtest.excludedGroups= -Dtest.groups=integration
```

**Cryptographic benchmarks** — no AWS required; runs on the local JVM only
```bash
mvn test -Dtest=BenchmarkSuite
```

**Cloud benchmarks** — requires deployed DynamoDB + KMS; measures real network latency and KMS call overhead
```bash
PQC_TABLE_NAME=pqc-items-dev PQC_KMS_KEY_ALIAS=alias/pqc-keystore-dev \
  mvn test -Dtest=CloudBenchmarkSuite
```

## Infrastructure

- **main.tf** — DynamoDB table (PAY_PER_REQUEST) + KMS key (AES-256, annual rotation) + IAM policy
- **variables.tf** — table_name (default: `pqc-items`), environment (default: `dev`), region (default: `eu-central-1`)
- **outputs.tf** — `table_arn`, `table_name`, `kms_key_id`, `kms_key_alias`, `iam_policy_arn`

### Deploy
```bash
cd infra/
terraform init
```

```bash
terraform apply
```
or for custom environment
```bash
terraform apply -var="environment=prod" -var="table_name=my-pqc-store" -var="region=eu-central-1"
```

Outputs: `table_arn`, `table_name`, `kms_key_alias`, `kms_key_id`, `iam_policy_arn`.

## Usage

```java
// Create framework — generates a fresh PqcKeyBundle in memory (ML-KEM-1024 + ML-DSA-65 + AES-256 DEK)
PqcFramework fw = PqcFrameworkImpl.create("pqc-items-dev", "eu-central-1");

// Store encrypted value (two-layer: AES-GCM at-rest + ML-KEM transit, signed with ML-DSA)
fw.putString("user:alice", "{\"role\":\"admin\"}");

// Retrieve and decrypt (verifies ML-DSA signature before decryption)
String value = fw.getString("user:alice").orElseThrow();

// Raw bytes
fw.put("blob:1", someByteArray);
Optional<byte[]> blob = fw.get("blob:1");

// Delete
fw.delete("user:alice");
```

### Multi-Bundle Encryption

By default every row is encrypted with the master key bundle. Pass an explicit `bundleId` to use (or auto-create) a separate bundle for specific rows:

```java
PqcFramework fw = PqcFrameworkImpl.create("pqc-items-dev", "eu-central-1");

// Master bundle — default, no bundleId needed
fw.putString("user:alice", "{\"role\":\"admin\"}");
fw.getString("user:alice");  // reads back with master

// Named bundle — auto-created on first use, stored as kid="audit-log" in DynamoDB
fw.putString("audit:2026-04-25", "login event", "audit-log");
fw.getString("audit:2026-04-25", "audit-log");  // must use same bundleId to read back

// Pre-populate a registry with an existing bundle loaded from KmsBlobKeyStore
KeyBundleRegistry registry = new KeyBundleRegistry(masterBundle, new InMemoryKeyManager());
registry.register("audit-log", keyStore.load(Path.of("audit-log.enc")));
PqcFramework fw2 = PqcFrameworkImpl.create("pqc-items-dev", "eu-central-1", registry);
```

> **Note:** Auto-created bundles live only in JVM heap. Persist them with `KmsBlobKeyStore.save()` before the process exits or the rows encrypted by them become permanently unreadable.

### Key Persistence

`PqcFrameworkImpl.create()` generates a fresh key bundle on every call — keys are held only in JVM memory. Without the same bundle, data written in a previous process is permanently unreadable. Use `KmsBlobKeyStore` to persist the bundle across restarts:

```java
KmsBlobKeyStore keyStore = KmsBlobKeyStore.create("eu-central-1", new AesGcmServiceImpl());

// First run: generate keys, write data, save bundle
PqcKeyBundle bundle = new InMemoryKeyManager().generateKeys();
PqcFrameworkImpl fw = PqcFrameworkImpl.create("pqc-items-dev", "eu-central-1", bundle);
fw.putString("user:alice", "{\"role\":\"admin\"}");
keyStore.save(bundle, Path.of("keystore.enc"), "alias/pqc-keystore-dev");

// Subsequent runs: load bundle, read existing data
PqcKeyBundle restored = keyStore.load(Path.of("keystore.enc"));
PqcFrameworkImpl fw2 = PqcFrameworkImpl.create("pqc-items-dev", "eu-central-1", restored);
fw2.getString("user:alice").orElseThrow();
```

**Blob format** — envelope encryption so the ~10 KB key material never touches KMS directly (4 KB limit):
```
[4-byte length][KMS-encrypted AES-256 data key] [AES-GCM( serialised PqcKeyBundle )]
```
The plaintext data key exists only in JVM heap during save/load and is zeroed immediately after use.

## Performance

Measured on AArch64 (Apple M-series), OpenJDK 25, n=1000 per primitive / n=500 per framework operation / n=50 per cloud operation.

### Cryptographic primitives

| Operation | Mean | Notes |
|-----------|------|-------|
| ML-KEM-1024 Encapsulation | 61.6 µs | vs. ECDH-P256 key agreement: 134.7 µs (2.2× faster) |
| ML-KEM-1024 Decapsulation | 58.1 µs | |
| ML-DSA-65 Signing | 137.7 µs | vs. ECDSA-P256 signing: 63.0 µs (2.2× slower) |
| ML-DSA-65 Verification | 86.6 µs | |
| AES-256-GCM Encrypt 256 B | 18.5 µs | |
| HMAC-SHA256 key derivation | 3.3 µs | |

### Framework operations (in-memory store, crypto only)

| Operation | Mean | Dominant cost |
|-----------|------|---------------|
| `put()` 256 B value | 395 µs | ML-KEM encaps (62 µs) + ML-DSA sign (138 µs) |
| `get()` 256 B value | 147 µs | ML-KEM decaps (58 µs) + ML-DSA verify (87 µs) |

### Real cloud deployment (eu-central-1, n=50)

| Operation | Mean | Notes |
|-----------|------|-------|
| DynamoDB PutItem baseline (unencrypted) | 25.2 ms | network RTT only |
| DynamoDB GetItem baseline (unencrypted) | 25.0 ms | |
| Framework `put()` 256 B (encrypted) | 29.8 ms | +4.6 ms over baseline; PQC = 1.3% of total |
| Framework `get()` 256 B (encrypted) | 26.6 ms | +1.6 ms over baseline; PQC = 0.6% of total |
| AWS KMS `GenerateDataKey` | 28.1 ms | per-record KMS pattern would add this per write |
| AWS KMS `Decrypt` | 27.3 ms | paid once per bundle load (not per record) |

**Key comparison:** ML-KEM encapsulation (61.6 µs) replaces a per-record KMS `GenerateDataKey` call (28.1 ms) — **456× faster**, while providing post-quantum security.

### Key management (one-time costs)

| Operation | Mean |
|-----------|------|
| Key bundle generation (ML-KEM-1024 + ML-DSA-65 + AES-256) | 740 µs |
| Key bundle serialization (~10 KB) | 7.5 µs |
| Key bundle deserialization (~10 KB) | 133 µs |

### Storage overhead per encrypted record

| Plaintext value | Stored bytes | Overhead ratio |
|----------------|-------------|----------------|
| 64 B | 5,093 B | 79.6× |
| 256 B | 5,285 B | 20.6× |
| 1,024 B | 6,053 B | 5.9× |
| 4,096 B | 9,125 B | 2.2× |
| 65,536 B | 70,565 B | 1.1× |

Fixed overhead per record: **4,926 B** (ML-DSA-65 signature 3,309 B + ML-KEM-1024 encapsulation 1,568 B + partition key 43 B + bundle ID 6 B).

---

## Algorithms

| Purpose | Algorithm | NIST Level | Notes |
|---------|-----------|------------|-------|
| Key encapsulation (transit) | ML-KEM-1024 | 5 (≥ AES-256) | 1568-byte encapsulation, 32-byte shared secret |
| Digital signatures (integrity) | ML-DSA-65 | 3 | 3309-byte signature |
| At-rest + transit payload encryption | AES-256-GCM | — | 12-byte random IV, 128-bit auth tag |
| Deterministic key derivation | HMAC-SHA256 | — | Enables exact `GetItem` lookups |

## DynamoDB Item Schema

| Attribute | Type | Content |
|-----------|------|---------|
| `pk` | S | HMAC-SHA256(DEK, plainKey) — Base64URL, no padding |
| `kid` | S | Key bundle ID that encrypted this row (e.g. `"master"`, `"bundle-b"`) |
| `kem` | B | ML-KEM-1024 encapsulation ciphertext |
| `payload` | B | AES-GCM(transitKey, serialised payload) |
| `sig` | B | ML-DSA-65 signature over `kem ‖ payload` |

## Dependencies

| Library                                                                  | Version | Purpose |
|--------------------------------------------------------------------------|---------|---------|
| [Bouncy Castle](https://www.bouncycastle.org/) `bcprov-jdk18on`          | 1.80 | ML-KEM, ML-DSA, AES-GCM via JCA |
| [AWS SDK for Java v2](https://github.com/aws/aws-sdk-java-v2) `dynamodb` | 2.29.52 | DynamoDB client |
| [AWS SDK for Java v2](https://github.com/aws/aws-sdk-java-v2) `kms`      | 2.29.52 | KMS envelope encryption for key bundle persistence |
| [JUnit 5]( https://junit.org/junit5/)                                    | 5.11.4 | Unit and integration testing |

---

## Author

Bc. Adam Antal
