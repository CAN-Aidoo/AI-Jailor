"""Tenant secret store: envelope-encrypted, write-only credentials for the egress broker.

Design (see RESEARCH_ALIGNMENT.md): we do not build a KMS. Each secret gets its own random
data key (DEK) used with AES-256-GCM; the DEK is wrapped by a key-encryption key (KEK) held by a
pluggable ``KeyProvider`` (local master keys here; AWS/GCP KMS or Vault Transit implement the same
two methods). Values are write-only through the API and are only ever decrypted in-process, to be
substituted into upstream requests by the broker, so a cell never sees them.
"""
