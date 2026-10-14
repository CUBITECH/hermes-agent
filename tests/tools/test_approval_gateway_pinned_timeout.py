"""Pinned per-request deadlines for gateway approval waits."""


def test_gateway_wait_uses_host_pinned_timeout(monkeypatch):
    from tools import approval
    from tools import approval_gateway_wait as wait

    session_key = "pinned-timeout"
    approval._gateway_queues.pop(session_key, None)
    approval._pending.pop(session_key, None)
    observed = []
    monkeypatch.setattr(wait._ctx, "_fire_approval_hook", lambda *_args, **_kwargs: None)

    def poll(_event, _session_key, *, interrupt_log, timeout_seconds=None):
        observed.append(timeout_seconds)
        return "timeout"

    monkeypatch.setattr(wait, "_poll_event", poll)
    decision = wait._await_gateway_decision(
        session_key,
        lambda _data: None,
        {
            "command": "<tool>",
            "description": "one exact decision",
            "pattern_key": "plugin_rule:request",
            "pattern_keys": ["plugin_rule:request"],
        },
        timeout_seconds=43_200,
    )

    assert decision["resolved"] is False
    assert observed == [43_200]
    assert session_key not in approval._gateway_queues


def test_gateway_coalescing_partitions_once_from_session_policy(monkeypatch):
    from tools import approval
    from tools import approval_gateway_wait as wait

    session_key = "policy-partition"
    leader = wait._ApprovalEntry({
        "command": "<tool>",
        "description": "one exact decision",
        "pattern_key": "plugin_rule:request",
        "pattern_keys": ["plugin_rule:request"],
        "allow_session": False,
        "allow_permanent": False,
    })
    approval._gateway_queues[session_key] = [leader]
    notified = []
    monkeypatch.setattr(wait._ctx, "_fire_approval_hook", lambda *_args, **_kwargs: None)

    def poll(event, _session_key, *, interrupt_log, timeout_seconds=None):
        assert event is not leader.event
        return "timeout"

    monkeypatch.setattr(wait, "_poll_event", poll)
    try:
        decision = wait._await_gateway_decision(
            session_key,
            lambda data: notified.append(data),
            {
                "command": "<tool>",
                "description": "ordinary decision",
                "pattern_key": "plugin_rule:request",
                "pattern_keys": ["plugin_rule:request"],
                "allow_session": True,
                "allow_permanent": True,
            },
        )
    finally:
        approval._gateway_queues.pop(session_key, None)

    assert decision["resolved"] is False
    assert len(notified) == 1


def test_gateway_pinned_timeout_never_coalesces(monkeypatch):
    from tools import approval
    from tools import approval_gateway_wait as wait

    session_key = "deadline-partition"
    leader = wait._ApprovalEntry({
        "command": "<tool>",
        "description": "ordinary decision",
        "pattern_key": "plugin_rule:request",
        "pattern_keys": ["plugin_rule:request"],
        "allow_session": True,
        "allow_permanent": True,
    })
    approval._gateway_queues[session_key] = [leader]
    observed = []
    monkeypatch.setattr(wait._ctx, "_fire_approval_hook", lambda *_args, **_kwargs: None)

    def poll(event, _session_key, *, interrupt_log, timeout_seconds=None):
        assert event is not leader.event
        observed.append(timeout_seconds)
        return "timeout"

    monkeypatch.setattr(wait, "_poll_event", poll)
    try:
        decision = wait._await_gateway_decision(
            session_key,
            lambda _data: None,
            dict(leader.data),
            timeout_seconds=2,
        )
    finally:
        approval._gateway_queues.pop(session_key, None)

    assert decision["resolved"] is False
    assert observed == [2]


def test_gateway_does_not_coalesce_behind_explicit_deadline_leader(monkeypatch):
    from tools import approval
    from tools import approval_gateway_wait as wait

    session_key = "explicit-leader"
    data = {
        "command": "<tool>",
        "description": "ordinary decision",
        "pattern_key": "plugin_rule:request",
        "pattern_keys": ["plugin_rule:request"],
        "allow_session": True,
        "allow_permanent": True,
    }
    leader = wait._ApprovalEntry(data, timeout_seconds=1)
    approval._gateway_queues[session_key] = [leader]
    notified = []
    monkeypatch.setattr(wait._ctx, "_fire_approval_hook", lambda *_args, **_kwargs: None)

    def poll(event, _session_key, *, interrupt_log, timeout_seconds=None):
        assert event is not leader.event
        return "timeout"

    monkeypatch.setattr(wait, "_poll_event", poll)
    try:
        decision = wait._await_gateway_decision(
            session_key,
            lambda value: notified.append(value),
            data,
        )
    finally:
        approval._gateway_queues.pop(session_key, None)

    assert decision["resolved"] is False
    assert len(notified) == 1


def test_gateway_rejects_scope_not_offered_by_target_entry():
    from tools import approval
    from tools.approval_gateway_wait import _ApprovalEntry

    session_key = "choice-policy"
    once_entry = _ApprovalEntry({
        "allow_session": False,
        "allow_permanent": False,
    })
    approval._gateway_queues[session_key] = [once_entry]
    try:
        assert approval.resolve_gateway_approval(
            session_key,
            "session",
            request_id=once_entry.data["request_id"],
        ) == 1
    finally:
        approval._gateway_queues.pop(session_key, None)

    assert once_entry.result == "deny"


def test_gateway_unhashable_choice_denies_and_releases_all_targets():
    from tools import approval
    from tools.approval_gateway_wait import _ApprovalEntry

    session_key = "unhashable-choice"
    entries = (_ApprovalEntry({}), _ApprovalEntry({}))
    approval._gateway_queues[session_key] = list(entries)

    assert approval.resolve_gateway_approval(
        session_key,
        ["session"],
        resolve_all=True,
    ) == 2

    assert session_key not in approval._gateway_queues
    assert [entry.result for entry in entries] == ["deny", "deny"]
    assert all(entry.event.is_set() for entry in entries)


def test_mcp_elicitation_forwards_explicit_gateway_timeout(monkeypatch):
    from tools import approval
    from tools import approval_context
    from tools import approval_prompt

    observed = {}
    monkeypatch.setattr(approval_context, "get_current_session_key", lambda: "mcp-session")
    monkeypatch.setattr(approval_context, "_is_gateway_approval_context", lambda: True)
    monkeypatch.setattr(approval, "_gateway_notify_cb", lambda _session: lambda _data: None)

    def await_decision(*args, **kwargs):
        observed.update(kwargs)
        return {"resolved": False, "choice": None}

    monkeypatch.setattr(
        approval_prompt._gw,
        "_await_gateway_decision",
        await_decision,
    )

    result = approval_prompt.request_elicitation_consent(
        "Allow MCP request?",
        "server request",
        timeout_seconds=17,
        surface="mcp-test",
    )

    assert result == "cancel"
    assert observed["timeout_seconds"] == 17
