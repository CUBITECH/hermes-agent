"""Behavior contracts for exact one-time plugin approval directives."""


def test_once_scoped_approve_is_enforced_by_host_gate(monkeypatch):
    from hermes_cli.plugins import PLUGIN_RUNTIME_CAPABILITIES, resolve_pre_tool_block

    assert {
        "pre-tool-approval-once-v1",
        "pre-tool-approval-min-timeout-v1",
    } <= PLUGIN_RUNTIME_CAPABILITIES

    seen = {}
    monkeypatch.setattr(
        "hermes_cli.plugins.invoke_hook",
        lambda hook_name, **kwargs: [{
            "action": "approve",
            "approval_scope": "once",
            "minimum_timeout_seconds": 43_200,
            "message": "why",
            "rule_key": "write_file:ssh",
        }],
    )

    def approve(_tool_name, _reason, **kwargs):
        seen.update(kwargs)
        return {"approved": True, "message": None}

    monkeypatch.setattr("tools.approval.request_tool_approval", approve)

    assert resolve_pre_tool_block("write_file", {}) is None
    assert seen == {
        "rule_key": "write_file:ssh",
        "one_time_only": True,
        "minimum_timeout_seconds": 43_200,
    }


def test_unknown_approval_scope_fails_closed(monkeypatch):
    from hermes_cli.plugins import resolve_pre_tool_block

    monkeypatch.setattr(
        "hermes_cli.plugins.invoke_hook",
        lambda hook_name, **kwargs: [{
            "action": "approve",
            "approval_scope": "forever",
            "message": "why",
        }],
    )

    message = resolve_pre_tool_block("write_file", {})

    assert message is not None
    assert "invalid approval_scope" in message


def test_invalid_minimum_timeout_fails_closed(monkeypatch):
    from hermes_cli.plugins import resolve_pre_tool_block

    monkeypatch.setattr(
        "hermes_cli.plugins.invoke_hook",
        lambda hook_name, **kwargs: [{
            "action": "approve",
            "approval_scope": "once",
            "minimum_timeout_seconds": "43200",
            "message": "why",
        }],
    )

    message = resolve_pre_tool_block("write_file", {})

    assert message is not None
    assert "invalid minimum_timeout_seconds" in message


def test_later_invalid_approve_fails_closed_after_valid_approve(monkeypatch):
    from hermes_cli.plugins import resolve_pre_tool_block

    monkeypatch.setattr(
        "hermes_cli.plugins.invoke_hook",
        lambda hook_name, **kwargs: [
            {"action": "approve", "message": "valid first"},
            {
                "action": "approve",
                "approval_scope": "once",
                "minimum_timeout_seconds": "43200",
            },
        ],
    )

    message = resolve_pre_tool_block("write_file", {})

    assert message is not None
    assert "invalid minimum_timeout_seconds" in message
