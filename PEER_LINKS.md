# Peer links: attested cell-to-cell channels

By default a cell can reach nothing but the egress broker (see NETWORKING.md), including other cells. A
**peer link** is the one explicit exception: two cells, with the consent of their owners, get an
end-to-end encrypted, mutually authenticated channel through the platform. It is the transport for
workloads that must exchange data across parties (for example the two sides of a joint computation).
It is a **channel**, not a protocol: it does not implement MPC, PSI, secret sharing or any other
privacy-preserving computation. Those run on top of it, inside the cells.

Enabled only when `PEER_ATTESTATION_SECRET` is set. Otherwise every peer endpoint answers
`peer_links_disabled` (503) and the proxy refuses peer CONNECTs.

## Lifecycle and consent

| Step | Who | Effect |
|---|---|---|
| `POST /v1/peer-links` `{cell_id, peer_cell_id, ttl_seconds?, purpose?}` | tenant owning `cell_id` (owner/admin) | creates the link `pending`; the other tenant's audit chain records the request. Links between two cells of **one** tenant are `active` at once. |
| `POST /v1/peer-links/{id}/accept` | tenant owning the responder cell only | `active` |
| `DELETE /v1/peer-links/{id}` | **either** party | `revoked`; a live session is cut immediately |
| `GET /v1/peer-links[?include_inactive=true]`, `GET /v1/peer-links/{id}` | parties (owner/admin/auditor) | everyone else gets the same 404 |
| `GET /v1/peer-links/attestation-key` | any reader | the platform's Ed25519 public key |

The initiator cell is the TLS client, the responder the TLS server. Both cells must be `running`/`ready`
and still owned by the agreed tenants **at every connection attempt** (not only at proposal time), and the
link must be unexpired. A link is revoked automatically when either cell stops or is destroyed. Peer cell
ids are shared out of band; a missing cell and a not-running cell give the same error so tenants cannot
probe for ids. Propose, accept, revoke and cell-loss are audited transactionally on **both** tenants' chains.

Limits: ttl 60 s to `PEER_LINK_MAX_TTL_SECONDS`; at most `PEER_LINK_MAX_OPEN_PER_TENANT` open links; one
open link per cell pair (either direction).

## Wire protocol

Each cell talks to **its own** proxy (the listener identifies the cell; a cell cannot claim to be another).

1. `CONNECT <link-id-hex32>.peer.aijailer.invalid:443` -> `200` or `403`. Every refusal (unknown link, not
   a party, revoked, expired, peer not running, side already attached) looks the same.
2. Cell -> hub, one line: `{"v":1,"cert_pem":"<its ephemeral certificate>"}`.
3. When both sides have arrived, hub -> each side, one line:
   `{"v":1,"attestation":<DSSE envelope>,"peer_cert_pem":"...","session_id":"..."}`.
4. Opaque relay. The cells run **mutual TLS 1.3 through it**, trusting only the attested peer certificate
   (compared by SHA-256 of the DER). The relay carries ciphertext only (`tests/peerlink` proves this with
   a tap on the wire).

The attestation is an in-toto Statement in a DSSE envelope signed with the platform's Ed25519 key,
predicate type `https://aijailer.dev/attestation/peer-link/v1`:
`{link_id, role, session_id, self{cell_id,tenant_id,cert_sha256}, peer{...}, issued_at, expires_at}`.
A client MUST check: platform signature; `link_id`; that `self` is **its own** certificate; that the
`peer_cert_pem` it was given hashes to the attested peer hash; expiry (300 s skew allowed); and, if it has
one, the out-of-band pin. Verifying only the signature is not enough.

**Client MUST NOT over-read.** The peer's first TLS bytes can arrive in the same segment as the
attestation line. A client that reads the line with a buffered reader and then hands the raw socket to a
TLS library loses them and the handshake hangs. Read the line byte-exactly, or feed the leftover buffer
to TLS first (the Go helper does the latter; so does the test peer).

## The cell-side client: `aijailer-peer`

Static Go binary (stdlib crypto only), installed at `/usr/sbin/aijailer-peer`. The platform injects
`AIJAILER_PEER_ATTEST_PUBKEY` and the proxy settings into every cell when peer links are enabled.

    aijailer-peer --link <32 hex> --stdio
    aijailer-peer --link <32 hex> --listen 127.0.0.1:7000 [--pin <peer cert sha256>] [--wait 90s]
                  [--identity-file /path --cert-hash-file /path]

The workload speaks plain bytes to stdio or to **one** local TCP connection; encryption and attestation
checks happen in the helper. Status goes to stderr as JSON lines (`listening`, `established` with the
peer's attested cell/tenant and certificate hashes, `closed`, `error`). Exit codes: 0 ok, 2 usage,
3 platform refused, 4 attestation rejected, 5 TLS failed, 6 other.

## What this does and does not protect

Protected:
- **The relay cannot read or alter the data.** It sees TLS 1.3 records between certificates it does not
  hold keys for. Tampering ends the session.
- **No cell can reach another without both owners' consent**, and consent is re-checked on every attach.
  A third cell, a revoked or expired link, a stopped cell: refused.
- **Each side learns who it is talking to** (cell and tenant) from a signed statement bound to the
  certificate it then actually authenticates in TLS.
- Sessions are bounded: wait timeout, lifetime, idle timeout and byte cap; revocation cuts them.

**Not** protected, stated plainly:
- **Identity rests on the platform's signature unless you pin.** A malicious or compromised platform could
  attest a certificate it controls and sit in the middle. To remove that, give each side a persistent
  `--identity-file`, exchange the two certificate hashes out of band, and pass them as `--pin`: a pinned
  peer cannot be impersonated even by the platform (`tests/peerlink` covers a hub substituting a
  certificate, with and without a pin).
- **The operator still sees metadata** (who connects to whom, when, how many bytes) and can deny service.
  Peer sessions are audited as network events. The operator can also read a cell's memory (see
  SECURITY_MODEL.md): this feature does not change the trust model for the cells themselves.
- No protocol for the actual joint computation is provided.

## Operating notes and limits

- The hub is **single-process**: sessions and revocation cuts live in the API process. Run one API
  instance for peer links, or add sticky routing, before scaling out.
- A link side holds one connection at a time; reconnect after a drop within the link's lifetime.
- Verified here: real sockets, real TLS, Python and Go peers against the real proxy and hub, SQLite for the
  lifecycle layer. Not verified here: a booted Firecracker guest running the helper (no KVM), PostgreSQL
  paths (row locks, migration `008_peer_links`).
