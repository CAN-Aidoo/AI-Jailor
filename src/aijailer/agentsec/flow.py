"""Information-flow labels (CaMeL-style capabilities).

Every value carries *provenance* (where it came from) and *readers* (who may
receive it). Combining values intersects readers and unions provenance, so a
secret can never be laundered into a less-restricted value by concatenation.
Policies are deterministic functions, not model judgements.
"""

from dataclasses import dataclass, field
from enum import Enum

PUBLIC = "*"  # reader wildcard: anyone may receive


class Source(str, Enum):
    USER = "user"                 # trusted instruction from the authenticated principal
    TOOL_OUTPUT = "tool_output"   # untrusted content returned by a tool / web page / file
    SECRET = "secret"             # credential or sensitive record
    MODEL = "model"               # derived by a quarantined model from untrusted data


@dataclass(frozen=True)
class Label:
    sources: frozenset = field(default_factory=frozenset)
    readers: frozenset = field(default_factory=lambda: frozenset({PUBLIC}))

    def can_flow_to(self, destination: str) -> bool:
        return PUBLIC in self.readers or destination in self.readers

    @property
    def untrusted(self) -> bool:
        return bool(self.sources & {Source.TOOL_OUTPUT, Source.MODEL})

    def combine(self, other: "Label") -> "Label":
        if PUBLIC in self.readers:
            readers = other.readers
        elif PUBLIC in other.readers:
            readers = self.readers
        else:
            readers = self.readers & other.readers
        return Label(self.sources | other.sources, readers)


def combine_all(labels) -> Label:
    out = Label()
    for lab in labels:
        out = out.combine(lab)
    return out


@dataclass(frozen=True)
class Labeled:
    value: object
    label: Label = field(default_factory=Label)

    @staticmethod
    def user(value) -> "Labeled":
        return Labeled(value, Label(frozenset({Source.USER})))

    @staticmethod
    def untrusted(value) -> "Labeled":
        return Labeled(value, Label(frozenset({Source.TOOL_OUTPUT})))

    @staticmethod
    def secret(value, readers: set[str]) -> "Labeled":
        return Labeled(value, Label(frozenset({Source.SECRET}), frozenset(readers)))


class FlowViolation(Exception):
    """A deterministic policy refused an action. Never retried or negotiated."""
