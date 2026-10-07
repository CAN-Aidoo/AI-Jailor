"""Behavioural tests for the dataflow taint analyzer (assert real verdicts)."""

import pytest

from aijailer.services.taint_tracker import SinkType, TaintTracker


@pytest.fixture
def t():
    return TaintTracker()


def sinks(t, code):
    return {v.sink_type for v in t.analyze(code).violations}


def test_sql_fstring_flagged(t):
    code = 'uid = request.args.get("id")\nq = f"SELECT * FROM u WHERE id={uid}"\ncursor.execute(q)\n'
    assert SinkType.SQL in sinks(t, code)


def test_parameterised_sql_clean(t):
    code = 'uid = request.args.get("id")\ncursor.execute("SELECT * FROM u WHERE id=%s", (uid,))\n'
    assert t.analyze(code).safe


def test_transitive_flow_through_helpers(t):
    code = "a = request.form['x']\nb = a.strip()\nc = [b, 'k']\nd = ','.join(c)\nos.system(d)\n"
    assert SinkType.COMMAND in sinks(t, code)


def test_sanitizer_removes_taint(t):
    code = 'from markupsafe import escape\nn = escape(request.form["n"])\nreturn_html = render(n)\n'
    assert t.analyze(code).safe


def test_overwrite_clears_taint(t):
    code = 'x = request.args["a"]\nx = "constant"\neval(x)\n'
    assert t.analyze(code).safe


def test_branch_merge_is_conservative(t):
    code = 'x = "ok"\nif flag:\n    x = request.args["a"]\neval(x)\n'
    assert SinkType.COMMAND in sinks(t, code)


def test_loop_carried_taint(t):
    code = 'acc = ""\nfor k in request.args:\n    acc = acc + k\nos.system(acc)\n'
    assert SinkType.COMMAND in sinks(t, code)


def test_subprocess_shell_true(t):
    code = 'import subprocess\ncmd = request.form["c"]\nsubprocess.run(cmd, shell=True)\n'
    assert SinkType.COMMAND in sinks(t, code)


def test_taint_inside_function_body(t):
    code = 'def h():\n    p = request.args["p"]\n    return open(p).read()\n'
    assert SinkType.FILE_PATH in sinks(t, code)


def test_int_cast_sanitizes(t):
    code = 'uid = int(request.args["id"])\ncursor.execute(f"SELECT * FROM u WHERE id={uid}")\n'
    assert t.analyze(code).safe


def test_unparseable_code_never_clean(t):
    res = t.analyze("def (:")
    assert res.parse_error and not res.safe


def test_unsupported_language_refuses(t):
    with pytest.raises(NotImplementedError):
        t.analyze("x", language="go")
