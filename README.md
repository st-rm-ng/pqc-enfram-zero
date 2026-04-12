# PQC EnFram Zero

Post-Quantum Cryptography Encryption Framework for Zero Trust Security is a client-side encryption library for AWS DynamoDB integrating **ML-KEM** (CRYSTALS-Kyber) and **ML-DSA** (CRYSTALS-Dilithium).

## Overview

PQC EnFram Zero adapts [CryptDB](https://css.csail.mit.edu/cryptdb/)'s onion encryption architecture for NoSQL key-value stores. All data is decrypted only on the client — DynamoDB stores exclusively ciphertext. The framework is transparent to callers: `put`/`get`/`delete` work like any KV store, encryption happens automatically.

### Security Principles

1. **Client-only plaintext** — no plaintext ever leaves the JVM process
2. **ML-KEM for data-in-transit** — a fresh ephemeral ML-KEM-1024 shared secret is generated per operation (forward secrecy per call)
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
    │   ├── framework/
    │   │   ├── PqcFramework.java
    │   │   ├── PqcFrameworkImpl.java
    │   │   └── IntegrityException.java
    │   └── FrameworkDemo.java
    └── test/java/org/pqc/enframzero/
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
- **KeyBundleSerializer.java** — Serialises all five key components to a compact binary format (`[4-byte length][bytes]` per field); used internally by `KmsBlobKeyStore`
- **KmsBlobKeyStore.java** — Persists a `PqcKeyBundle` across JVM restarts using KMS envelope encryption: `GenerateDataKey` → AES-GCM encrypt the serialised bundle → write blob to file; on load: `Decrypt` the envelope DEK → AES-GCM decrypt → deserialise

### `org.pqc.enframzero.onion`

- **OnionLayer.java** — Enum with three levels: `PLAIN` (no transformation), `DET` (deterministic — same input always produces the same output), `RND` (randomised — fresh IV per call)
- **KeyOnion.java** — Transforms plaintext keys per layer: `DET` = `HMAC-SHA256(DEK, key)` encoded as Base64URL; `RND` = `AES-GCM(DEK, key)`; `PLAIN` = passthrough
- **ValueOnion.java** — At-rest encryption layer: `AES-GCM(DEK, value)` with a fresh 12-byte random IV per write; same value written twice always produces different ciphertext
- **TransitEnvelope.java** — Immutable record carrying `kemEncapsulation`, `encryptedPayload`, and `dsaSignature`; inner payload is serialised as `[4-byte length][deterministicKey][encryptedValue]`

### `org.pqc.enframzero.store`

- **EncryptedStore.java** — Interface: `put(deterministicKey, TransitEnvelope)` / `get(deterministicKey) → Optional<TransitEnvelope>` / `delete(deterministicKey)`; implement this to target any KV backend
- **DynamoDbEncryptedStore.java** — AWS DynamoDB implementation: maps `TransitEnvelope` fields to Binary attributes (`pk`, `kem`, `payload`, `sig`) and back using AWS SDK v2 `DynamoDbClient`

### `org.pqc.enframzero.framework`

- **PqcFramework.java** — Public API interface: `put(key, byte[])`, `get(key) → Optional<byte[]>`, `delete(key)`; default `putString` / `getString` convenience overloads (UTF-8)
- **PqcFrameworkImpl.java** — Wires all modules together and orchestrates the full encryption/decryption flow; `create(table, region)` generates a fresh key bundle; `create(table, region, bundle)` accepts an existing `PqcKeyBundle` loaded from `KmsBlobKeyStore`
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
| `framework/PqcFrameworkRoundTripTest` | Unit | 7 | put/get, overwrite, delete, multi-key, integrity check |
| `keys/KmsBlobKeyStoreIntegrationTest` | Integration | 2 | Save/load round-trip via KMS, cross-restart read of existing DynamoDB data |
| `store/DynamoDbEncryptedStoreIntegrationTest` | Integration | 1 | put/get/delete against a live DynamoDB table |

**39 unit tests** — no AWS infrastructure required.
**3 integration tests** — tagged `@Tag("integration")` and excluded by default.

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

### Demo

```bash
mvn exec:java -Dexec.mainClass=org.pqc.enframzero.FrameworkDemo
```

runs **[FrameworkDemo.java](src/main/java/org/pqc/enframzero/FrameworkDemo.java)** — 8 scenarios against live DynamoDB + KMS

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
