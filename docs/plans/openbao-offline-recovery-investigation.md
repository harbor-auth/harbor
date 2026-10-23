# OpenBao auto-unseal with independent offline recovery

Investigated 2026-09-08. Production was not changed.

## Live OVH offline-decryption proof — 2026-09-08

**Passed with genuine US-region OVH ciphertext and an exported OVH-generated
software AES-256 key.** This supersedes the earlier uncertainty about whether
OVH ciphertext can be decrypted independently. It does not yet prove an
OpenBao snapshot restore or an OVH-compatible recovery endpoint.

After IAM setup, mTLS key listing returned HTTP 200. Created two disposable
resources named `harbor-offline-test-aes` and
`harbor-offline-test-transport`. The latter contains only a locally generated
RSA-4096 public transport key. No production OpenBao configuration changed.

Test steps and results:

1. OVH generated a SOFTWARE AES-256 encrypt/decrypt key and encrypted a
   randomly generated 32-byte payload using an empty context, matching the
   OpenBao wrapper's API usage.
2. Imported the local RSA transport public key, enabled AES-key extraction,
   exported the AES key wrapped using RSA-OAEP-256 in JWK format, then disabled
   extraction again successfully.
3. A separate Python process, with socket creation/network connections blocked,
   used the local transport private key to decrypt the exported JWE. It decoded
   the recovered oct JWK and used that AES key to decrypt the original OVH
   ciphertext. Recovered bytes exactly matched the original payload.
4. Wrong AES key and tampered ciphertext both failed authentication.

Observed formats:

- Ordinary encryption: compact JWE, `alg=dir`, `enc=A256GCM`,
  `x-key-ver=0`. Protected header bytes are the AES-GCM additional authenticated
  data. No extra derivation was required for this tested key/version/context.
- Wrapped export: compact JWE, `alg=RSA-OAEP-256`, `enc=A256GCM`;
  decrypted JWK contains `k`, `kty`, `kid`, and `key_ops`.
- US import rejected top-level type/operations alongside `keys`; importing a
  public JWK with its own `key_ops` and only a top-level name succeeded.
- RAW export did not decode to a bare 32-byte AES key (524 bytes observed).
  Its internal structure was not investigated; JWK export worked explicitly.

Scripts: `/tmp/harbor-ovh-live-lab/test.py` and
`/tmp/harbor-ovh-live-lab/offline.py`. Disposable artifacts, including the local
transport private key and encrypted export, are retained under ignored
`keys/recovery-test/` with restrictive permissions for the next shim test.
The two disposable OVH resources remain. These artifacts are development test
material, not an approved production backup custody arrangement. Plaintext
key material was not printed. The offline decryptor did not write decrypted
service-key material to disk.

Next: implement authenticated metadata/encrypt/decrypt compatibility and test
native OpenBao startup and Raft snapshot recovery with OVH access blocked.
Test key versions, rotation, and backup compatibility before production use.

## Finding

**Updated direction:** the static-seal design below is not the selected
security posture. It puts an additional long-lived wrapping key in production
memory. Investigate native OVH sealing with an offline copy of the actual OVH
service key instead. The previous disposable test proves only static-seal
recovery; it does not prove recovery of OVH-sealed data.

### Native OVH seal with emergency recovery outside OVH

Source inspection establishes:

- OVH documents wrapped export of eligible SOFTWARE service keys. HSM keys
  are currently excluded. Export must be arranged before an outage. The RSA
  transport private key can stay on a separate recovery machine; production
  receives neither the transport private key nor the exported service key.
- OpenBao's OVH wrapper envelope-encrypts root material with a random local
  data-encryption key. It stores the OVH encryption of that key in
  `BlobInfo.KeyInfo.WrappedKey`, alongside the local ciphertext and IV.
- OVH SDK v0.5.2 explicitly describes its Encrypt response as JWE. Decrypt
  sends that string to OVH. The wrapper uses an empty OVH context.
- Therefore an offline implementation of that JWE decryption, using the
  exported service key, is a plausible way to recover the envelope key.
  OpenBao's existing EnvelopeDecrypt then handles the second layer.
- This is a source-based feasibility finding, not a tested interoperability
  guarantee: no actual OVH ciphertext/export pair was available in this
  investigation. The precise JWE algorithms, any key derivation and metadata
  requirements still need verification against real OVH output.

Candidate integration: an emergency OVH-compatible endpoint on a separate
recovery machine, reached over authenticated TLS, using dedicated recovery
credentials. Keep the native seal plugin and key identifiers; change the
endpoint explicitly during recovery. The wrapper also calls GetServiceKey
at configuration time, so a decrypt-only command is insufficient. The endpoint
must implement required metadata and encryption/decryption operations, and
its compatibility with startup and migration must be tested. This is custom
recovery tooling, not a documented OpenBao offline-unseal feature.

Normal operation leaves the OVH wrapping key outside production. During
recovery the backup key is loaded only on the recovery machine (or potentially
into compatible hardware). OpenBao still has its own decrypted operational
keys in memory, and Harbor still signs locally; this does not change either
fact. An offline exported key also gives its custodian an independent path to
decrypt stolen storage, so backup custody is part of the security boundary.

Required proof before adoption:

1. Create a disposable eligible OVH software key; export it wrapped to an
   offline-held transport key (or import an offline-generated service key).
2. Encrypt a known random envelope key using the actual OVH API; disconnect
   OVH access and recover identical bytes locally from that real ciphertext.
3. Initialize a disposable OpenBao Raft cluster using the native OVH plugin;
   save a snapshot and a known Transit ciphertext.
4. Block OVH access, restore and unseal through the recovery endpoint; verify
   the original Transit ciphertext decrypts. Test tampering and wrong keys.
5. Test migration away from the recovery endpoint, key rotation and historical
   snapshots before adopting the design in production.

Inspected sources: wrapping repository commit
`97c565d2b7914bb420d01e86fd0284c46c2922a0`, OVH SDK v0.5.2
(`33668c45a2f329e7ce976a9712cde635c64b3d9e`), and OVH CLI main.
The CLI's ordinary decrypt command also calls OVH; no ready-made offline
replacement was found in that path.

References: [OVH SDK encryption interface](https://github.com/ovh/okms-sdk-go/blob/v0.5.2/apis.go),
[native seal configuration](https://openbao.org/docs/configuration/seal/ovhcloud/),
[OVH CLI decrypt implementation](https://github.com/ovh/okms-cli/blob/main/cmd/okms/keys/decrypt.go),
and the wrapper and BYOK documentation linked below.

### Upstream recovery work checked 2026-09-08

Searched issues and PRs across the OpenBao organization, including the wrapping
and plugin repositories. No dedicated exported-OVH-key offline recovery issue
or implementation was found. Related upstream work is substantial:

- [Issue #299](https://github.com/openbao/openbao/issues/299) remains open:
  asks for recovery when the auto-unseal provider is unavailable.
- [Emergency Seal RFC](https://openbao.org/community/rfcs/emergency-seal/),
  merged as [PR #1830](https://github.com/openbao/openbao/pull/1830) on
  2026-01-26, proposes an independent Shamir emergency seal alongside KMS.
  This solves provider-independent recovery without exporting the KMS key.
  It requires newly provisioned emergency shares, not existing recovery shares.
  Root-key rotation would be blocked while the primary KMS is unavailable.
- [Parallel Unseal RFC PR #3464](https://github.com/openbao/openbao/pull/3464)
  merged on 2026-07-13, but changes documentation only. It expands recovery to
  multiple independent seals/providers. Its author described tentative plans
  for emergency seal in 2.7 or early 2.8 and parallel unseal in 2.8+; this is
  not a release commitment.
- [Issue #450](https://github.com/openbao/openbao/issues/450), multiple KMS
  keys for auto-unseal, remains open.

Both RFC proof-of-concept sections still say TBD. No open emergency-seal
implementation PR was found. The current main branch CLI at
`internal/command/operator_unseal.go` has reset/migrate options but lacks the
RFC's `-seal` selection option. Treat these as accepted designs awaiting
implementation, not deployable features. The exported-OVH-key experiment
remains a separate compatibility task; these RFCs do not prove it works.

### Earlier static-seal experiment (not selected)

OpenBao 2.6.1 supports a static AES-256 seal. It can consume a 32-byte key
from a file. A separate startup helper can obtain this key by asking an
external KMS to decrypt an encrypted copy. An operator can supply an offline
copy of the same static key when that KMS is unavailable. OpenBao sees the
same seal type, key identifier, and key bytes in both cases.

This is a feasible design, not a finished Harbor integration. It does not
require exporting the provider's KMS master key. The offline backup is our
own OpenBao static seal key. This is not OpenBao's recovery-share mechanism.

## Source findings

- [Static seal](https://openbao.org/docs/configuration/seal/static/): built-in,
  supports `file://`, current/previous keys and identifiers; recommends an
  existing trusted secrets source and careful injection.
- [Seal lifecycle](https://openbao.org/docs/concepts/seal/): recovery shares
  cannot replace an unavailable auto-unseal KMS; changing seal types requires
  a migration, backup, and availability of the old seal.
- [OVH wrapper source](https://github.com/openbao/go-kms-wrapping/blob/main/wrappers/ovhcloudkms/ovhcloudkms.go):
  envelope-encrypts data locally and asks OVH to encrypt the envelope key.
  Configuration also contacts OVH to validate key operations. A raw key file
  cannot simply substitute for this wrapper.
- [OVH import/export](https://docs.ovhcloud.com/en/guides/manage-and-operate/kms/import-export-keys-byok):
  documents eligible software-key import/export, but excludes HSM-protected
  keys from that mechanism. This is unnecessary for the proposed static-seal
  design: encrypt/decrypt our static key as payload instead.

## Disposable test

Image: `openbao/openbao:2.6.1`, digest
`sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0`.

Used a randomly generated disposable seal key, file storage and a container
with `--network none`. Initialized OpenBao and wrote a KV marker. Stopped it,
removed its seal-key file, and confirmed startup failed. Restored the same key
and identifier, restarted, and confirmed `sealed=false` and the original KV
marker was readable. Removed the container, disposable key file and test data.

Passed:

- Missing seal key prevents startup.
- Offline key restores access to existing encrypted data without networking.

Not tested: live OVH calls, helper implementation, Shamir-to-static migration,
Raft snapshot restore, Kubernetes injection, multi-provider failover, or HA.
The local test script remains at `/tmp/harbor-static-seal-lab/test.py`;
it contains no production credentials.

## Proposed deployment

1. Generate our own random 32-byte static seal key and permanent identifier.
2. Create a protected offline backup, with custody separate from production.
3. Encrypt the static key through the selected KMS; store ciphertext and its
   required metadata with recovery/configuration artifacts.
4. At startup, a least-privilege helper decrypts that ciphertext and writes
   the result to restricted, memory-backed storage for OpenBao to read.
5. On KMS failure, fail closed. An explicit operator recovery path injects
   the offline copy without running the failed fetch helper again.
6. Retain historical seal keys/identifiers for the lifetime of backups that
   require them. Test rotation and backup compatibility.

Two independent KMSs could each encrypt the same static key, letting the
helper retrieve it from either provider. This needs implementation and tests;
it is not native parallel unseal. Any one recovery path plus the encrypted
OpenBao storage is sufficient to recover secrets, so each path needs strong
access controls. The providers must not depend on Harbor for their bootstrap
credentials or share a failure domain inadvertently.

## Security tradeoff and release gates

The static seal key exists in helper/OpenBao memory and briefly in an injected
file. This gives up non-exportable seal-key custody in exchange for independent
recovery. Do not persist plaintext seal material in Git, Helm values,
ordinary Kubernetes Secrets, logs, image layers, or beside the data backups.
Memory-backed storage also requires host/swap/crash-dump controls. A compromised
host can still access plaintext memory; this design does not protect against it.

Before production: implement the helper and offline injection path; test wrong
and missing keys, KMS timeouts, optional provider failover and cleanup; rehearse
Shamir-to-static migration on a disposable Raft cluster; restore a snapshot
with all KMS access blocked; verify previously stored Transit ciphertext is
decryptable and Harbor can load existing signing keys. Fix seal readiness and
alerting. Only then migrate using the existing unseal custodians.
