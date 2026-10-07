"""Taint Tracker service.

Tracks data flow labels through code ASTs to detect when
tainted (user-controlled) data reaches sensitive sinks
without proper sanitization. Uses tree-sitter for AST parsing.
"""

import ast
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
    UNTAINTED = "untainted"         # Known-clean (constants)


class SinkType(str, Enum):
    """Types of sensitive data sinks."""
    SQL_QUERY = "sql_query"
    HTML_OUTPUT = "html_output"
    FILE_PATH = "file_path"
    SUBPROCESS_ARG = "subprocess_arg"
    LOG_MESSAGE = "log_message"
    ERROR_RESPONSE = "error_response"
    NETWORK_REQUEST = "network_request"
    # Short aliases (same values)
    SQL = "sql_query"
    COMMAND = "subprocess_arg"


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
        """Analyze source code and return taint violations."""
        return self.analyze(code, language).violations

    def analyze(self, code: str, language: str = "python") -> "TaintAnalysis":
        """Run dataflow taint analysis.

        Python is analysed with a real forward dataflow pass over the stdlib
        AST (variable environments, branch merge, loop fixpoint, sanitizer
        and parameterised-query recognition). Other languages are not yet
        supported and are rejected explicitly rather than silently passed.
        """
        if language != "python":
            raise NotImplementedError(
                f"taint analysis for '{language}' not implemented; refusing to report 'clean'"
            )
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            # Unparseable code can never be certified.
            return TaintAnalysis(
                violations=[TaintViolation(
                    sink_type=SinkType.SUBPROCESS_ARG,
                    source_label=TaintLabel.UNTAINTED,
                    location=f"line {exc.lineno}",
                    message=f"Code does not parse: {exc.msg}",
                    severity="CRITICAL",
                )],
                parse_error=True,
            )
        visitor = _FlowAnalyzer(self)
        visitor.run(tree)
        logger.info("taint.analysis_complete", violation_count=len(visitor.violations))
        return TaintAnalysis(violations=visitor.violations, tainted_vars=visitor.final_tainted)


@dataclass
class TaintAnalysis:
    """Result of analysing a code unit."""
    violations: list[TaintViolation] = field(default_factory=list)
    tainted_vars: dict[str, TaintLabel] = field(default_factory=dict)
    parse_error: bool = False

    @property
    def safe(self) -> bool:
        return not self.violations


_SOURCE_ROOTS = {"request", "flask.request"}
_SOURCE_CALLS = {"input", "os.getenv", "os.environ.get", "sys.stdin.read", "sys.stdin.readline"}
_SOURCE_ATTRS = {"sys.argv": TaintLabel.USER_INPUT, "os.environ": TaintLabel.ENVIRONMENT}
_FILE_SOURCES = {"open().read", "read_file"}

_SQL_SINKS = {"execute", "executemany", "raw_query"}
_HTML_SINKS = {"render", "HTMLResponse", "Markup", "format_html", "render_template_string"}
_PATH_SINKS = {"open", "Path", "os.path.join", "read_file", "write_file", "os.remove"}
_EXEC_SINKS = {"eval", "exec", "os.system", "os.popen"}
_PROC_SINKS = {"subprocess.run", "subprocess.call", "subprocess.Popen",
               "subprocess.check_output", "subprocess.check_call"}
_NET_SINKS = {"requests.get", "requests.post", "urllib.request.urlopen", "httpx.get", "httpx.post"}
_LOG_SINKS = {"logger.info", "logger.debug", "logger.warning", "logger.error", "logging.info", "print"}
_SANITIZERS = {
    "escape", "markupsafe.escape", "html.escape", "html_escape", "sanitize_input",
    "validate_input", "shlex.quote", "int", "float", "bool", "uuid.UUID", "bleach.clean",
    "input_validator.validate", "output_encoder.encode", "safe_query_builder.parameterize",
}


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func) + "()")
    return ".".join(reversed(parts))


class _FlowAnalyzer:
    """Forward dataflow over one module; functions analysed with fresh env."""

    def __init__(self, tracker: TaintTracker) -> None:
        self.tracker = tracker
        self.violations: list[TaintViolation] = []
        self._seen: set[tuple] = set()
        self.final_tainted: dict[str, TaintLabel] = {}

    # -- environment helpers --
    def run(self, tree: ast.Module) -> None:
        env: dict[str, TaintLabel] = {}
        self._block(tree.body, env)
        self.final_tainted = {k: v for k, v in env.items() if self._bad(v)}

    @staticmethod
    def _bad(label: TaintLabel | None) -> bool:
        return label not in (None, TaintLabel.UNTAINTED, TaintLabel.SANITIZED, TaintLabel.CERTIFIED)

    @staticmethod
    def _join(a: TaintLabel | None, b: TaintLabel | None) -> TaintLabel | None:
        order = [TaintLabel.USER_INPUT, TaintLabel.ENVIRONMENT, TaintLabel.FILE_SYSTEM,
                 TaintLabel.DATABASE]
        for lab in order:
            if lab in (a, b):
                return lab
        return a or b

    def _merge(self, a: dict, b: dict) -> dict:
        out = dict(a)
        for k, v in b.items():
            out[k] = self._join(out.get(k), v)
        return out

    # -- statements --
    def _block(self, stmts: list[ast.stmt], env: dict) -> None:
        for st in stmts:
            self._stmt(st, env)

    def _stmt(self, st: ast.stmt, env: dict) -> None:
        if isinstance(st, ast.Assign):
            lab = self._expr(st.value, env)
            for t in st.targets:
                self._assign(t, lab, env)
        elif isinstance(st, ast.AnnAssign) and st.value is not None:
            self._assign(st.target, self._expr(st.value, env), env)
        elif isinstance(st, ast.AugAssign):
            lab = self._join(self._expr(st.value, env), self._expr(st.target, env))
            self._assign(st.target, lab, env)
        elif isinstance(st, (ast.Expr, ast.Return)) and st.value is not None:
            self._expr(st.value, env)
        elif isinstance(st, ast.If):
            self._expr(st.test, env)
            a, b = dict(env), dict(env)
            self._block(st.body, a)
            self._block(st.orelse, b)
            env.clear()
            env.update(self._merge(a, b))
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            lab = self._expr(st.iter, env)
            for _ in range(2):  # small fixpoint
                self._assign(st.target, lab, env)
                body = dict(env)
                self._block(st.body, body)
                env.update(self._merge(env, body))
            self._block(st.orelse, env)
        elif isinstance(st, ast.While):
            for _ in range(2):
                self._expr(st.test, env)
                body = dict(env)
                self._block(st.body, body)
                env.update(self._merge(env, body))
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                lab = self._expr(item.context_expr, env)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, lab, env)
            self._block(st.body, env)
        elif isinstance(st, ast.Try):
            branches = []
            for blk in [st.body, *[h.body for h in st.handlers], st.orelse]:
                e = dict(env)
                self._block(blk, e)
                branches.append(e)
            merged = branches[0]
            for e in branches[1:]:
                merged = self._merge(merged, e)
            env.clear()
            env.update(merged)
            self._block(st.finalbody, env)
        elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._block(st.body, {})  # parameters are not assumed tainted
        elif isinstance(st, ast.ClassDef):
            self._block(st.body, {})

    def _assign(self, target: ast.AST, lab: TaintLabel | None, env: dict) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = lab
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign(elt, lab, env)
        elif isinstance(target, ast.Attribute | ast.Subscript):
            base = _dotted(target.value) if isinstance(target, ast.Attribute) else _dotted(
                target.value)
            if base:
                env[base] = self._join(env.get(base), lab)

    # -- expressions --
    def _expr(self, node: ast.AST | None, env: dict) -> TaintLabel | None:
        if node is None or isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.Name):
            return env.get(node.id)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            dotted = _dotted(node if isinstance(node, ast.Attribute) else node.value)
            root = dotted.split(".")[0]
            if root in _SOURCE_ROOTS or dotted in _SOURCE_ATTRS:
                return _SOURCE_ATTRS.get(dotted, TaintLabel.USER_INPUT)
            if isinstance(node, ast.Subscript):
                self._expr(node.slice, env)
            inner = self._expr(node.value, env)
            return inner if inner is not None else env.get(dotted)
        if isinstance(node, ast.JoinedStr):
            lab = None
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    lab = self._join(lab, self._expr(v.value, env))
            return lab
        if isinstance(node, ast.Call):
            return self._call(node, env)
        if isinstance(node, ast.BinOp):
            return self._join(self._expr(node.left, env), self._expr(node.right, env))
        if isinstance(node, (ast.BoolOp,)):
            lab = None
            for v in node.values:
                lab = self._join(lab, self._expr(v, env))
            return lab
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            lab = None
            for v in node.elts:
                lab = self._join(lab, self._expr(v, env))
            return lab
        if isinstance(node, ast.Dict):
            lab = None
            for v in node.values:
                lab = self._join(lab, self._expr(v, env))
            return lab
        if isinstance(node, ast.IfExp):
            return self._join(self._expr(node.body, env), self._expr(node.orelse, env))
        if isinstance(node, ast.Await):
            return self._expr(node.value, env)
        if isinstance(node, ast.FormattedValue):
            return self._expr(node.value, env)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            e = dict(env)
            for gen in node.generators:
                self._assign(gen.target, self._expr(gen.iter, e), e)
            return self._expr(node.elt, e)
        return None

    def _call(self, node: ast.Call, env: dict) -> TaintLabel | None:
        name = _dotted(node.func)
        arg_labels = [self._expr(a, env) for a in node.args]
        kw = {k.arg: self._expr(k.value, env) for k in node.keywords}
        joined = None
        for lab in [*arg_labels, *kw.values()]:
            joined = self._join(joined, lab)
        # receiver taint for method calls like user.strip()
        if isinstance(node.func, ast.Attribute):
            recv = self._expr(node.func.value, env)
        else:
            recv = None

        self._check_sinks(node, name, arg_labels, kw)

        if name in _SANITIZERS or name.split(".")[-1] in {"escape", "quote"}:
            return TaintLabel.SANITIZED
        if name in _SOURCE_CALLS or (name.split(".")[0] in _SOURCE_ROOTS):
            return TaintLabel.USER_INPUT
        if name.startswith("safe_") or "certified_components" in name:
            return TaintLabel.CERTIFIED
        if name.endswith((".fetchall", ".fetchone", ".fetchmany")):
            return TaintLabel.DATABASE
        return self._join(joined, recv)

    # -- sinks --
    def _report(self, node: ast.AST, sink: SinkType, lab: TaintLabel, name: str,
                severity: str = "HIGH", note: str = "") -> None:
        key = (node.lineno, node.col_offset, sink)
        if key in self._seen:
            return
        self._seen.add(key)
        self.violations.append(TaintViolation(
            sink_type=sink, source_label=lab, location=f"line {node.lineno}:{node.col_offset}",
            message=f"Tainted data ({lab.value}) reaches {sink.value} sink {name}() "
                    f"without sanitization{note}",
            severity=severity,
        ))

    def _check_sinks(self, node: ast.Call, name: str, args: list, kw: dict) -> None:
        last = name.split(".")[-1]
        tainted_args = [a for a in args if self._bad(a)]
        any_tainted = tainted_args[0] if tainted_args else next(
            (v for v in kw.values() if self._bad(v)), None)
        if any_tainted is None and not (name in _EXEC_SINKS and args):
            return
        if last in _SQL_SINKS or name in _SQL_SINKS:
            # Parameterised form: query (arg 0) is clean, data travels in later args.
            if args and not self._bad(args[0]):
                return
            self._report(node, SinkType.SQL_QUERY, args[0] if args else any_tainted, name,
                         "CRITICAL")
        elif name in _EXEC_SINKS:
            if self._bad(args[0] if args else None):
                self._report(node, SinkType.SUBPROCESS_ARG, args[0], name, "CRITICAL")
        elif name in _PROC_SINKS:
            shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value
                        for k in node.keywords)
            if self._bad(args[0] if args else None) or (shell and any_tainted):
                self._report(node, SinkType.SUBPROCESS_ARG, any_tainted, name, "CRITICAL")
        elif last in _HTML_SINKS or name in _HTML_SINKS:
            self._report(node, SinkType.HTML_OUTPUT, any_tainted, name)
        elif name in _PATH_SINKS or last in {"open"}:
            self._report(node, SinkType.FILE_PATH, any_tainted, name)
        elif name in _NET_SINKS:
            self._report(node, SinkType.NETWORK_REQUEST, any_tainted, name, "HIGH")
        elif name in _LOG_SINKS:
            if any_tainted in (TaintLabel.USER_INPUT,):
                self._report(node, SinkType.LOG_MESSAGE, any_tainted, name, "LOW")


# Singleton
_tracker: TaintTracker | None = None


def get_taint_tracker() -> TaintTracker:
    global _tracker
    if _tracker is None:
        _tracker = TaintTracker()
    return _tracker
