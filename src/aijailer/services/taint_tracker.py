"""Taint Tracker service.

Tracks data flow labels through code ASTs to detect when
tainted (user-controlled) data reaches sensitive sinks
without proper sanitization. Uses tree-sitter for AST parsing.
"""

from enum import Enum
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)


class TaintLabel(str, Enum):
    """Data flow classification labels."""
    USER_INPUT = "user_input"       # From HTTP request, form, CLI
    DATABASE = "database"           # From DB query results
    FILE_SYSTEM = "file_system"     # From file reads
    ENVIRONMENT = "environment"     # From env vars
    SANITIZED = "sanitized"         # Passed through validator
    CERTIFIED = "certified"         # Output of certified component


class SinkType(str, Enum):
    """Types of sensitive data sinks."""
    SQL_QUERY = "sql_query"
    HTML_OUTPUT = "html_output"
    FILE_PATH = "file_path"
    SUBPROCESS_ARG = "subprocess_arg"
    LOG_MESSAGE = "log_message"
    ERROR_RESPONSE = "error_response"
    NETWORK_REQUEST = "network_request"


@dataclass
class TaintViolation:
    """A detected taint flow violation."""
    sink_type: SinkType
    source_label: TaintLabel
    location: str  # file:line description
    message: str
    severity: str = "HIGH"


@dataclass
class ASTNode:
    """Simplified AST node for taint analysis."""
    node_type: str
    name: str = ""
    value: str = ""
    children: list["ASTNode"] = field(default_factory=list)
    taint: TaintLabel | None = None
    line: int = 0
    col: int = 0


class TaintTracker:
    """Tracks data flow labels through the AST.

    Rules:
    - Taint propagates through operations (assignment, concat, etc.)
    - Taint is removed ONLY by certified sanitizers
    - CERTIFIED + USER_INPUT = USER_INPUT (conservative)
    """

    # Known sanitizer function names
    SANITIZERS = {
        "input_validator.validate",
        "safe_query_builder.parameterize",
        "output_encoder.encode",
        "html_escape",
        "sanitize_input",
        "validate_input",
    }

    # Sink patterns: function names that are sensitive sinks
    SINK_PATTERNS = {
        SinkType.SQL_QUERY: [
            "execute", "raw_query", "cursor.execute", "db.execute",
            "session.execute", "connection.execute",
        ],
        SinkType.HTML_OUTPUT: [
            "render", "render_template", "Response", "HTMLResponse",
            "Markup", "format_html",
        ],
        SinkType.FILE_PATH: [
            "open", "Path", "os.path.join", "read_file", "write_file",
        ],
        SinkType.SUBPROCESS_ARG: [
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "os.system", "os.popen", "exec", "eval",
        ],
        SinkType.LOG_MESSAGE: [
            "logger.info", "logger.debug", "logger.warning",
            "logger.error", "logging.info", "print",
        ],
    }

    def propagate(self, node: ASTNode) -> TaintLabel | None:
        """Determine the taint label for a node based on its inputs.

        Taint propagation rules:
        - If any input is tainted and not sanitized, output is tainted
        - If node is a certified sanitizer, output is SANITIZED
        - Conservative: mixed taint = most dangerous taint
        """
        # Check if this node is a sanitizer
        if node.name in self.SANITIZERS or any(
            s in node.name for s in self.SANITIZERS
        ):
            return TaintLabel.SANITIZED

        # Check if this is a certified component output
        if "certified_components" in node.name or node.name.startswith("safe_"):
            return TaintLabel.CERTIFIED

        # Propagate taint from children
        child_taints = [
            self.propagate(child) for child in node.children
        ]
        child_taints = [t for t in child_taints if t is not None]

        if not child_taints:
            return node.taint

        # Conservative rule: USER_INPUT dominates all
        if TaintLabel.USER_INPUT in child_taints:
            return TaintLabel.USER_INPUT

        # FILE_SYSTEM and ENVIRONMENT are also tainted
        for dangerous in [TaintLabel.FILE_SYSTEM, TaintLabel.ENVIRONMENT, TaintLabel.DATABASE]:
            if dangerous in child_taints:
                return dangerous

        return child_taints[0] if child_taints else None

    def check_sink(self, node: ASTNode, sink_type: SinkType) -> TaintViolation | None:
        """Check if tainted data reaches a sensitive sink.

        Returns a violation if tainted (non-sanitized) data
        flows into the specified sink type.
        """
        taint = self.propagate(node)

        if taint is None or taint in (TaintLabel.SANITIZED, TaintLabel.CERTIFIED):
            return None

        # Check if this node matches a sink pattern
        sink_patterns = self.SINK_PATTERNS.get(sink_type, [])
        is_sink = any(pattern in node.name for pattern in sink_patterns)

        if not is_sink:
            return None

        return TaintViolation(
            sink_type=sink_type,
            source_label=taint,
            location=f"line {node.line}:{node.col}",
            message=f"Tainted data ({taint.value}) reaches {sink_type.value} sink "
                    f"at {node.name} without sanitization",
        )

    def analyze_code(self, code: str, language: str = "python") -> list[TaintViolation]:
        """Analyze source code for taint violations.

        Uses tree-sitter for AST parsing when available,
        falls back to pattern-based analysis otherwise.
        """
        violations = []

        try:
            violations = self._analyze_with_tree_sitter(code, language)
        except (ImportError, Exception) as e:
            logger.warning(
                "taint.tree_sitter_unavailable",
                error=str(e),
                msg="Falling back to pattern-based analysis",
            )
            violations = self._analyze_with_patterns(code)

        logger.info("taint.analysis_complete", violation_count=len(violations))
        return violations

    def _analyze_with_tree_sitter(self, code: str, language: str) -> list[TaintViolation]:
        """Parse with tree-sitter and run taint analysis on AST."""
        import tree_sitter_python as tspython
        from tree_sitter import Language, Parser

        PY_LANGUAGE = Language(tspython.language())
        parser = Parser(PY_LANGUAGE)
        tree = parser.parse(bytes(code, "utf-8"))

        violations = []
        self._walk_tree_sitter_node(tree.root_node, violations, code)
        return violations

    def _walk_tree_sitter_node(self, node, violations: list, source: str):
        """Recursively walk tree-sitter AST and check for taint violations."""
        # Check for dangerous patterns
        if node.type == "call":
            func_name = source[node.start_byte:node.end_byte]
            for sink_type, patterns in self.SINK_PATTERNS.items():
                for pattern in patterns:
                    if pattern in func_name:
                        # Check if arguments contain tainted sources
                        for child in node.children:
                            if child.type == "argument_list":
                                arg_text = source[child.start_byte:child.end_byte]
                                if self._looks_tainted(arg_text):
                                    violations.append(TaintViolation(
                                        sink_type=sink_type,
                                        source_label=TaintLabel.USER_INPUT,
                                        location=f"line {node.start_point[0] + 1}",
                                        message=f"Potentially tainted data in {pattern} call",
                                    ))

        for child in node.children:
            self._walk_tree_sitter_node(child, violations, source)

    def _looks_tainted(self, text: str) -> bool:
        """Heuristic check if a code fragment contains tainted data."""
        taint_indicators = [
            "request.", "form.", "args.", "input(", "sys.argv",
            "environ", "f\"", "f'", ".format(", "% ", "+ ",
        ]
        return any(indicator in text for indicator in taint_indicators)

    def _analyze_with_patterns(self, code: str) -> list[TaintViolation]:
        """Fallback: pattern-based taint analysis without tree-sitter."""
        violations = []
        lines = code.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Check for string formatting in SQL contexts
            if any(kw in stripped for kw in ["execute(", "cursor.", "db."]):
                if any(fmt in stripped for fmt in ["f\"", "f'", ".format(", "% ", "+ "]):
                    violations.append(TaintViolation(
                        sink_type=SinkType.SQL_QUERY,
                        source_label=TaintLabel.USER_INPUT,
                        location=f"line {i}",
                        message="Possible SQL injection: string formatting in database query",
                    ))

            # Check for unescaped output
            if any(kw in stripped for kw in ["render(", "HTMLResponse(", "Markup("]):
                if "request." in stripped or "form." in stripped:
                    violations.append(TaintViolation(
                        sink_type=SinkType.HTML_OUTPUT,
                        source_label=TaintLabel.USER_INPUT,
                        location=f"line {i}",
                        message="Possible XSS: user input in HTML output without encoding",
                    ))

            # Check for subprocess with user input
            if any(kw in stripped for kw in ["subprocess.", "os.system(", "os.popen(", "eval(", "exec("]):
                if "request." in stripped or "input(" in stripped:
                    violations.append(TaintViolation(
                        sink_type=SinkType.SUBPROCESS_ARG,
                        source_label=TaintLabel.USER_INPUT,
                        location=f"line {i}",
                        message="Possible command injection: user input in subprocess/eval",
                    ))

        return violations


# Singleton
_tracker: TaintTracker | None = None


def get_taint_tracker() -> TaintTracker:
    global _tracker
    if _tracker is None:
        _tracker = TaintTracker()
    return _tracker
