# SafeHub cryptography

This crate is the client-side cryptographic boundary described in the SafeHub
paper. The server receives opaque MLS framing and encrypted payloads, never
group secrets or repository plaintext.

## Implemented

- A real OpenMLS repository group using
  `MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87` (NIST Category 5).
- ML-DSA-87 device credentials and serialized, single-use MLS KeyPackages.
- Repository group creation, Welcome-based joins, member commit processing,
  and self-update/rotation for post-compromise healing.
- Ciphertext-only MLS application messages for collaboration metadata.
- Domain-separated MLS exporters for `safehub-v1:transport` (λ = 384-bit DKR
  seed / `ss_e`) and `safehub-v1:refs` (256-bit `mk_e`), bound to the
  repository ID and zeroized on drop.
- Committing AES-256-GCM with padding-fix key commitment and outer
  HMAC-SHA-512-256 (Encrypt-then-MAC).
- Interval DKR with λ = 384-bit segment tokens, forward/backward blocks, and
  HKDF epoch keys `K_e` (AES-256); `StubDkr` is an alias of `IntervalDkr`.
- SHA-512 for collision-critical CAS / head digests; `blake3_512` helper only
  for non-collision-critical local indexing (not BHT/CNS margins).

The OpenMLS source is a nested clone at `../../vendor/openmls`, currently
tracking upstream commit `583525677abcc1710b2cc38bdc132550ed987f0e`.

## Parameter posture (paper §6 / appendix D)

| Target | Value | Notes |
|--------|-------|-------|
| Collision digests (CAS / heads) | SHA-512 | BHT ~170-bit, CNS ~204-bit |
| Outer AEAD / epoch tags | HMAC-SHA-512-256 | Ideal forgery 256-bit |
| DKR / RO length λ | 384 bits | Window soundness |
| Domain prefix | `safehub-v1:` | |
| MLS suite | Cat-5 ML-KEM-1024 / ML-DSA-87 / AES-256-GCM / SHA-512 | |
| AES-256 confidentiality | Grover floor **128** | Cat-5 baseline; not >128 |

Integrity and collision margins are sized for >128-bit quantum attack cost.
AES-256 key search under Grover remains the 128-bit Category-5 floor.

## Build and test

From `code/`:

```sh
cargo check -p safehub-crypto --features openmls
cargo test -p safehub-crypto --features openmls
```

The `openmls` feature is explicit so non-crypto server builds do not compile
the large post-quantum dependency graph. Product/client builds must enable it;
the default `stub` feature is development-only and provides no MLS security.

## Security boundary and limitations

This is foundation code, not a completed security product. OpenMLS owns MLS
state and its in-memory provider storage. Production work still needs durable
encrypted storage, OS-keychain anchoring, credential/CA verification,
administrator-signature policy, all-device removal, secure secret zeroization
auditing, delivery replay/fork handling, and interoperability vectors.

The paper calls for a libcrux-backed Category-5 provider. Upstream's current
libcrux provider advertises only X25519 suites and the X-Wing draft suite; the
required ML-KEM-1024/ML-DSA-87 suite is currently implemented by OpenMLS's
RustCrypto provider. Migrating that suite to libcrux remains blocked on
provider support upstream or a local provider implementation.
