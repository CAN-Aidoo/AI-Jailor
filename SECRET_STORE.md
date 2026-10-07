# Tenant Secret Store — operations guide

Write-only credentials the egress broker injects into outbound requests (see `API_DOCUMENTATION.md`,
"Secrets"). Each secret is encrypted with its own AES-256-GCM data key (DEK); the DEK is wrapped by a
key-encryption key (KEK) that lives either in **AWS KMS (recommended)** or in local master keys.

## Choosing a KEK provider

| Setting | Result |
|---|---|
| `SECRETS_KMS_KEY_ID` (+ AWS credentials from the instance/pod role) | AWS KMS is the primary KEK. Key material never reaches this process. |
| `SECRETS_MASTER_KEYS` only | Local master keys (development, small deployments). Anyone who can read the process env/memory has them. |
| both | KMS primary, local keys **decrypt-only fallback** — the migration state, see below. |
| neither | Store disabled: `/v1/secrets` returns 503. There is no default key. |

AWS settings: `SECRETS_KMS_KEY_ID` (key id, ARN or alias of a **symmetric** customer-managed key),
`SECRETS_KMS_REGION`, `SECRETS_KMS_ENDPOINT_URL` (LocalStack/testing), `SECRETS_KMS_ALLOWED_KEY_IDS`
(previous key ARNs, decrypt only), `SECRETS_KMS_CACHE_TTL_SECONDS` (default 300). Install with
`pip install 'aijailer[kms]'`. Credentials are never configured here: use the standard AWS chain.

### IAM policy for the control plane role

```json
{ "Effect": "Allow",
  "Action": ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"],
  "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY-ID" }
```
Nothing else: no `kms:GenerateDataKey*`, no `kms:ReEncrypt*`, no key administration. The key policy should
keep key administrators and key users separate.

### What KMS sees and logs (CloudTrail)

Every wrap/unwrap carries this **encryption context**: `tenant_id`, `secret_name`, and
`aijailer:aad-sha256` (a hash binding version, destination hosts and expiry). KMS authenticates it, so a
wrapped key cannot be replayed onto another tenant/name or after the hosts/expiry were edited in the database.
Secret *names* and tenant ids are therefore visible in CloudTrail (values and DEKs never are). You can write key-policy
conditions on `kms:EncryptionContext:tenant_id`.

## Behaviour under failure

| Situation | Behaviour |
|---|---|
| KMS outage / throttling / IAM problem | `KeyUnavailableError` = **transient**. Periodic refresh keeps running cells' current brokers; a change-triggered refresh (rotate/revoke) installs a broker with **no secrets** (fail closed). API returns 503. Never reported as tampering. |
| Row fails KMS/GCM authentication | Row skipped, `integrity_failure` audit event, other rows unaffected. |
| Row names a key we do not trust/know | Row skipped, `key_missing` audit event. |
| Boot with an unhealthy key | `secrets.key_provider_unhealthy` logged at CRITICAL; service starts; every operation retries, so it heals without restart. |

`startup_check` verifies the key exists, is Enabled and symmetric, and that this principal can actually Encrypt+Decrypt.

## Key rotation

* **Automatic KMS rotation** (enable on the key): the key ARN does not change; nothing to do.
* **New key (manual rotation)**: 1) set `SECRETS_KMS_KEY_ID` to the new key and put the old key's ARN in
  `SECRETS_KMS_ALLOWED_KEY_IDS`; 2) call `SecretStore.rewrap_all()` until `remaining` is 0 (re-wraps the DEKs, never
  decrypts values, ciphertext unchanged); 3) remove the old ARN and revoke the old key.
* **Local -> KMS migration**: set `SECRETS_KMS_KEY_ID` *and keep* `SECRETS_MASTER_KEYS`; run `rewrap_all()` to
  `remaining: 0`; then remove `SECRETS_MASTER_KEYS`.

## Emergency kill switch

Disabling the KMS key (or revoking the role's `kms:Decrypt`) stops new unwraps immediately; a process keeps using
DEKs it cached for up to `SECRETS_KMS_CACHE_TTL_SECONDS` (and brokers keep values already loaded until the next
refresh). Set the TTL to `0` to trade KMS calls for an immediate kill switch. Deleting a secret or calling the API
revokes it for running cells at once regardless.

## Limits

* Decrypted values and cached DEKs live in process memory by necessity.
* Injection is header-only and scoped per tenant (not per cell).
* No rollback protection against restoring an entire older consistent row.
* Only AWS KMS is implemented; GCP KMS / Vault Transit need the same five-method `KeyProvider` interface
  (`primary_key_id`, `wrap`, `unwrap`, `owns`, optional `check`) and nothing else changes.
* Single control-plane process per node (shared limitation of the network runtime).
