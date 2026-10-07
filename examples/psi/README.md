# Two-party PSI demo (reference workload for peer links)

A worked example of what runs **on top of** a peer link ([PEER_LINKS.md](../../PEER_LINKS.md)): two
parties find the items they have in common without revealing the rest. The platform provides the
attested, encrypted channel; this directory provides the computation. `psi.py` is one file, standard
library only (the stock guest image has Python 3.12 and no `cryptography` package).

**It is a demonstration, not a vetted implementation.** See "What it does not give you".

## What each side learns

| | receiver | sender |
|---|---|---|
| the intersection | **yes** | no |
| the other side's non-matching items | no | no |
| the other side's set size | yes | yes |

## Protocol

DDH-based PSI (Meadows 1986; Huberman, Franklin, Hogg 1999) in the RFC 3526 2048-bit group, the
order-q subgroup of quadratic residues. `H` hashes an item into that subgroup (SHA-512, expanded, then
squared) and is keyed by an agreed *context* string (use the peer link id).

    receiver -> sender : H(x)^a            for each x in X, in X's order
    sender   -> receiver: (H(x)^a)^b       for each of those, same order
                          sorted { H(s)^b  for each s in S }
    receiver: computes (H(s)^b)^a, intersects with its own (H(x)^a)^b values

`a` and `b` are fresh random keys per run. Every element received is checked to be in the subgroup
(a Jacobi symbol, validated against `v^q mod p` in the tests), which rejects 0, 1, p-1 and every
non-residue, so a peer cannot send small-order elements to extract key bits. Counts are bounded before
anything is allocated.

## Running it

Locally, two terminals, no platform involved:

    python3 psi.py --role sender   --items b.txt --context demo --listen  127.0.0.1:7000
    python3 psi.py --role receiver --items a.txt --context demo --connect 127.0.0.1:7000

Across two cells on a peer link (after `POST /v1/peer-links` and `accept`, with `$LINK` the 32-hex
`link_id`), inside each cell:

    aijailer-peer --link $LINK --listen 127.0.0.1:7000 &
    python3 psi.py --role receiver --items mine.txt --context $LINK --connect 127.0.0.1:7000   # on one side
    python3 psi.py --role sender   --items mine.txt --context $LINK --connect 127.0.0.1:7000   # on the other

`psi.py` retries the local connection until the helper is up, so start order does not matter. The
helper does the attestation checks and mutual TLS 1.3; the program only ever sees a plain local
socket. The roles are independent of the link's initiator/responder roles. Items are lines of the
file (surrounding whitespace stripped, blanks ignored, duplicates collapsed) and compared
byte-for-byte: normalise case and format first. The receiver prints the intersection to stdout, one
item per line, in its own order; both sides print a JSON status line to stderr and exit 0 on success.
`psi.py` is not installed in the base rootfs; ship it into the cell with your workload.

## What it does not give you

- **Only honest-but-curious security.** A malicious sender can lie about its set or the results;
  nothing proves the sender used the set it claims.
- **Low-entropy identifiers are not protected.** The receiver may put any items in its set, so if the
  items are phone numbers, e-mail addresses or small ID ranges, it can enumerate every candidate and
  learn the sender's whole set. That is inherent to PSI, not a bug of this code. Use high-entropy
  identifiers or restrict what each side may submit.
- Set sizes are revealed to both sides. Not constant-time. No protection against a peer that aborts
  midway after seeing the result.
- **Slow by design of the demo**: about 0.1 s per item pair (two real processes, one core each, 200
  items per side took 23 s on the development machine) because every item costs several 2048-bit
  exponentiations in pure Python. Fine for a demo with hundreds of items, not for millions. Elliptic
  curves and native code are the obvious next step; for production use a reviewed library (OpenMined
  PSI, Private Join and Compute).

## Tests

`tests/peerlink/test_psi.py`: the group constant is recomputed from its defining formula and checked
to be a safe prime; correctness across overlapping, disjoint, identical, empty, duplicate and binary
inputs; the wire carries neither items nor unblinded hashes, runs are unlinkable, the sender's set
leaves sorted; malformed, out-of-group, oversized and truncated messages are errors, not crashes; and
the whole stack (PSI -> `aijailer-peer` -> real proxy and relay -> mutual TLS). Eight deliberately
broken variants (no subgroup check, unsorted set, unblinded send, no final unblinding, context
ignored, no reply-count check, no count bound, constant key) are each caught.
