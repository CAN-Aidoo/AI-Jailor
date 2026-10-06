"""Host network enforcement for cells.

A cell's only network is a point-to-point TAP link to the host. nftables makes
that link terminate at exactly one service: the cell's egress broker. See
``nft.py`` for the ruleset and ``docs`` in RESEARCH_ALIGNMENT.md for the rationale.
"""
