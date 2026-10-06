"""Agent-action security: information-flow control and the egress broker.

The isolation layer (microVM) contains *code*. This package governs what a
contained agent may *do with data*: where values came from, who may read
them, and which network destinations may receive them. It follows the
capability / information-flow-control design from CaMeL (arXiv 2503.18813)
rather than relying on the model to resist prompt injection.
"""
