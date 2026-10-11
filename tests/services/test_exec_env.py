"""The per-command environment of POST /exec: validation, and that it really reaches the engine."""

import pytest

from aijailer.core.exceptions import AiJailerError
from aijailer.core.exec_env import (
    MAX_NAME_LEN,
    MAX_TOTAL_BYTES,
    MAX_VALUE_BYTES,
    MAX_VARS,
    MAX_CWD_LEN,
    REDACTED,
    managed_reason,
    redact_environment,
    validate_exec_environment,
    validate_working_directory,
)


def refused(env):
    with pytest.raises(AiJailerError) as e:
        validate_exec_environment(env)
    assert e.value.code == "invalid_environment"
    return e.value.message


def test_ordinary_variables_pass_unchanged_and_are_copied():
    env = {"DEBUG": "true", "path_like": "/a:/b", "_X1": "", "UNICODE": "naïve ☃", "A_B_C": "a=b c"}
    out = validate_exec_environment(env)
    assert out == env and out is not env
    assert validate_exec_environment(None) == {} and validate_exec_environment({}) == {}


def test_overriding_path_and_lang_is_allowed():
    assert validate_exec_environment({"PATH": "/x", "LANG": "de_DE.UTF-8"}) == {"PATH": "/x", "LANG": "de_DE.UTF-8"}


@pytest.mark.parametrize("name", ["", "A=B", "1A", "A B", "A-B", "Ä", "A\x00B", "a.b", "A\n", "$X", "A" * (MAX_NAME_LEN + 1)])
def test_malformed_names_are_refused(name):
    refused({name: "x"})


def test_a_name_at_the_limit_is_fine():
    validate_exec_environment({"A" * MAX_NAME_LEN: "x"})


def test_nul_in_a_value_is_refused_and_names_the_variable():
    assert "TOKEN" in refused({"TOKEN": "x\x00y"})


def test_size_limits():
    validate_exec_environment({"A": "x" * MAX_VALUE_BYTES})
    assert "A" in refused({"A": "x" * (MAX_VALUE_BYTES + 1)})
    refused({"A": "é" * (MAX_VALUE_BYTES // 2 + 1)})                       # limits are in bytes, not characters
    validate_exec_environment({f"V{i}": "x" for i in range(MAX_VARS)})
    refused({f"V{i}": "x" for i in range(MAX_VARS + 1)})
    per = MAX_TOTAL_BYTES // 9 + 1
    refused({f"V{i}": "x" * min(per, MAX_VALUE_BYTES) for i in range(10)})   # each fine, together too large


@pytest.mark.parametrize("name", [
    "http_proxy", "HTTP_PROXY", "Http_Proxy", "https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY",
    "AIJAILER_PEER_ATTEST_PUBKEY", "aijailer_anything", "AIJAILER_",
    "HOME", "USER",
])
def test_names_the_platform_or_the_agent_manage_are_refused_not_ignored(name):
    assert name in refused({"OK": "1", name: "x"})
    assert managed_reason(name)


@pytest.mark.parametrize("name", ["ALL_PROXY", "FTP_PROXY", "HOMEDIR", "USERNAME", "MY_AIJAILER_X", "home", "user", "PROXY"])
def test_similar_looking_names_are_not_swept_up(name):
    assert managed_reason(name) is None
    validate_exec_environment({name: "x"})


def test_validation_does_not_mutate_its_input():
    env = {"A": "1"}
    validate_exec_environment(env)
    assert env == {"A": "1"}


# ---------------------------------------------------------------- working directory
def cwd_refused(path):
    with pytest.raises(AiJailerError) as e:
        validate_working_directory(path)
    assert e.value.code == "invalid_working_directory"
    return e.value.message


def test_no_working_directory_means_the_guests_default_not_the_cell_default():
    assert validate_working_directory(None) is None
    assert validate_working_directory("") is None


@pytest.mark.parametrize("path", ["/", "/tmp", "/home/agent/project", "/a b/c", "/naïve/☃", "/x/../y", "//double"])
def test_absolute_paths_pass_unchanged(path):
    assert validate_working_directory(path) == path


@pytest.mark.parametrize("path", ["relative", "./here", "../up", "~", "~/x", " /leading-space", "C:\\win"])
def test_non_absolute_paths_are_refused(path):
    assert "absolute" in cwd_refused(path)


def test_nul_and_overlong_paths_are_refused():
    assert "NUL" in cwd_refused("/tmp/a\x00b")
    validate_working_directory("/" + "a" * (MAX_CWD_LEN - 1))
    assert str(MAX_CWD_LEN) in cwd_refused("/" + "a" * MAX_CWD_LEN)


# ---------------------------------------------------------------- redaction for the execution record
def test_redaction_keeps_every_name_and_drops_every_value():
    env = {"API_TOKEN": "s3cr3t", "DEBUG": "true", "X": "", "DB_URL": "postgres://u:p@h/db", "naïve": "☃"}
    out = redact_environment(env)
    assert set(out) == set(env)
    assert set(out.values()) == {REDACTED}
    for value in env.values():
        if value:
            assert value not in str(out)


def test_redaction_covers_names_a_secret_heuristic_would_miss():
    """Why every value goes, not just those named TOKEN/KEY/SECRET."""
    assert redact_environment({"AUTH": "Bearer abc", "X": "hunter2"}) == {"AUTH": REDACTED, "X": REDACTED}


def test_redaction_of_nothing_is_an_empty_dict_and_never_aliases_the_input():
    assert redact_environment(None) == {} and redact_environment({}) == {}
    env = {"A": "1"}
    out = redact_environment(env)
    out["B"] = "2"
    assert env == {"A": "1"}


def test_redaction_leaves_its_input_untouched_so_the_guest_still_gets_the_real_values():
    env = {"API_TOKEN": "s3cr3t"}
    redact_environment(env)
    assert env == {"API_TOKEN": "s3cr3t"}
