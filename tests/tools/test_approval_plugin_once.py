"""Exact one-time semantics for plugin-escalated approvals."""

import pytest


@pytest.fixture(autouse=True)
def approval_state():
    from tools import approval

    saved_sessions = {
        key: set(values) for key, values in approval._session_approved.items()
    }
    saved_permanent = set(approval._permanent_approved)
    approval._session_approved.clear()
    approval._permanent_approved.clear()
    try:
        yield approval
    finally:
        approval._session_approved.clear()
        approval._session_approved.update(saved_sessions)
        approval._permanent_approved.clear()
        approval._permanent_approved.update(saved_permanent)


def test_once_only_gate_hides_and_rejects_broader_scopes(
    approval_state, monkeypatch,
):
    offered = {}

    def choose_session(*_args, **kwargs):
        offered.update(kwargs)
        return "session"

    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"approvals": {"mode": "manual"}},
    )

    result = approval_state.request_tool_approval(
        "write_file",
        "plugin requires one exact decision",
        rule_key="request-specific",
        approval_callback=choose_session,
        one_time_only=True,
    )

    assert offered["allow_session"] is False
    assert offered["allow_permanent"] is False
    assert result["approved"] is False
    assert result.get("outcome") == "denied"
    assert not approval_state._session_approved
    assert not approval_state._permanent_approved


@pytest.mark.parametrize(("mode", "yolo"), [("off", False), ("manual", True)])
def test_once_only_gate_ignores_existing_approval_and_bypasses(
    approval_state, monkeypatch, mode, yolo,
):
    pattern = "plugin_rule:request-specific"
    approval_state._session_approved["test-session"] = {pattern}
    approval_state._permanent_approved.add(pattern)
    called = []

    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    if yolo:
        monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    else:
        monkeypatch.delenv("HERMES_YOLO_MODE", raising=False)
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"approvals": {"mode": mode}},
    )
    monkeypatch.setattr(
        "tools.approval.get_current_session_key", lambda: "test-session",
    )

    result = approval_state.request_tool_approval(
        "write_file",
        "plugin requires one exact decision",
        rule_key="request-specific",
        approval_callback=lambda *_args, **_kwargs: called.append(True) or "once",
        one_time_only=True,
    )

    assert called == [True]
    assert result["approved"] is True
    assert approval_state._session_approved["test-session"] == {pattern}
    assert approval_state._permanent_approved == {pattern}


def test_once_only_gate_never_uses_unattended_autoapprove(
    approval_state, monkeypatch,
):
    monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {
            "approvals": {"mode": "manual", "single_query_mode": "approve"},
        },
    )

    result = approval_state.request_tool_approval(
        "write_file",
        "plugin requires one exact decision",
        one_time_only=True,
    )

    assert result["approved"] is False
    assert "no interactive user" in result["message"]


def test_prompt_forwards_pinned_timeout_to_compatible_cli_callback():
    from tools.approval_prompt import prompt_dangerous_approval

    observed = {}

    def callback(_command, _description, **kwargs):
        observed.update(kwargs)
        return "once"

    result = prompt_dangerous_approval(
        "<tool>",
        "one exact decision",
        timeout_seconds=43_200,
        allow_permanent=False,
        allow_session=False,
        approval_callback=callback,
    )

    assert result == "once"
    assert observed["timeout_seconds"] == 43_200


@pytest.mark.parametrize(
    ("is_cli", "is_gateway", "is_ask"),
    [(False, True, False), (True, True, False), (True, False, True)],
)
def test_once_only_builtin_gateway_without_bound_transport_is_rejected(
    approval_state, monkeypatch, is_cli, is_gateway, is_ask,
):
    monkeypatch.setattr(
        approval_state,
        "_presence",
        lambda _callback=None: (None, is_cli, is_gateway, is_ask),
    )
    monkeypatch.setattr(
        "tools.approval_context._get_approval_transport_config",
        lambda: ("builtin", None),
    )
    monkeypatch.setattr(
        "tools.approval_context._get_approval_timeout",
        lambda: 43_200,
    )

    result = approval_state.request_tool_approval(
        "write_file",
        "one exact decision",
        one_time_only=True,
        minimum_timeout_seconds=43_200,
    )

    assert result["approved"] is False
    assert result["outcome"] == "transport_unsupported_surface"


def test_once_only_gateway_transport_failure_never_falls_back_to_builtin(
    approval_state, monkeypatch,
):
    class MissingTransportManager:
        @staticmethod
        def get_approval_transport(_name):
            return None

    monkeypatch.setattr(
        approval_state,
        "_presence",
        lambda _callback=None: (None, False, True, False),
    )
    monkeypatch.setattr(
        "tools.approval_context._get_approval_transport_config",
        lambda: ("missing", "builtin"),
    )
    monkeypatch.setattr(
        "tools.approval_context._get_approval_timeout",
        lambda: 43_200,
    )
    monkeypatch.setattr(
        "tools.approval_prompt.get_plugin_manager",
        lambda: MissingTransportManager(),
    )
    monkeypatch.setattr(
        approval_state,
        "_await_gateway_decision",
        lambda *_args, **_kwargs: pytest.fail("built-in gateway fallback was used"),
    )

    result = approval_state.request_tool_approval(
        "write_file",
        "one exact decision",
        one_time_only=True,
        minimum_timeout_seconds=43_200,
    )

    assert result["approved"] is False
    assert result["outcome"] == "transport_unavailable"


@pytest.mark.parametrize("failure", ["invalid", "stale", "error", "timeout"])
def test_once_only_gateway_transport_failures_ignore_builtin_fallback(
    approval_state, monkeypatch, failure,
):
    class SelectedTransport:
        present = staticmethod(lambda _request: None)

    class SelectedTransportManager:
        @staticmethod
        def get_approval_transport(_name):
            return SelectedTransport()

    class FailedDecision:
        choice = "deny"

        def __init__(self, value):
            self.failure = value

    monkeypatch.setattr(
        approval_state,
        "_presence",
        lambda _callback=None: (None, False, True, False),
    )
    monkeypatch.setattr(
        "tools.approval_context._get_approval_transport_config",
        lambda: ("phone", "builtin"),
    )
    monkeypatch.setattr(
        "tools.approval_context._get_approval_timeout",
        lambda: 43_200,
    )
    monkeypatch.setattr(
        "tools.approval_prompt.get_plugin_manager",
        lambda: SelectedTransportManager(),
    )
    monkeypatch.setattr(
        "hermes_cli.approval_transport.invoke_approval_transport",
        lambda *_args, **_kwargs: FailedDecision(failure),
    )
    monkeypatch.setattr(
        approval_state,
        "_await_gateway_decision",
        lambda *_args, **_kwargs: pytest.fail("built-in gateway fallback was used"),
    )

    result = approval_state.request_tool_approval(
        "write_file",
        "one exact decision",
        one_time_only=True,
        minimum_timeout_seconds=43_200,
    )

    assert result["approved"] is False
    assert result["outcome"] == f"transport_{failure}"
