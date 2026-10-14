"""Selection and approval resolution for ``pre_tool_call`` directives."""
from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
import logging
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PreToolCallDirective:
    action: Optional[str] = None
    message: Optional[str] = None
    rule_key: Optional[str] = None
    approval_scope: Optional[str] = None
    minimum_timeout_seconds: Optional[int] = None
    modified_args: Optional[Dict[str, Any]] = None


def select_pre_tool_call_directive(
    tool_name: str,
    args: Optional[Dict[str, Any]],
    hook_results: List[Any],
    allowed: Optional[set[str]],
    deny_message_format: str,
) -> PreToolCallDirective:
    """Apply modify aggregation and block-before-approve precedence."""
    if allowed is not None and tool_name not in allowed:
        return PreToolCallDirective(
            action="block",
            message=deny_message_format.format(tool_name=tool_name),
        )
    modified_args: Optional[Dict[str, Any]] = None
    first_approve: Optional[
        Tuple[Optional[str], Optional[str], Optional[str], Optional[int]]
    ] = None
    for result in hook_results:
        if not isinstance(result, dict):
            continue
        action = result.get("action")
        if action == "modify":
            partial = result.get("args")
            if isinstance(partial, dict) and partial:
                modified_args = {
                    **(modified_args if modified_args is not None else
                       (args if isinstance(args, dict) else {})),
                    **partial,
                }
            continue
        if action not in ("block", "approve"):
            continue
        message = result.get("message")
        message = message if isinstance(message, str) and message else None
        if action == "block" and not message:
            continue
        if action == "block":
            return PreToolCallDirective(
                action="block", message=message, modified_args=modified_args,
            )
        approval_scope = result.get("approval_scope")
        if approval_scope not in (None, "once"):
            return PreToolCallDirective(
                action="block",
                message="BLOCKED: plugin returned invalid approval_scope",
                modified_args=modified_args,
            )
        minimum_timeout_seconds = result.get("minimum_timeout_seconds")
        if minimum_timeout_seconds is not None and (
            approval_scope != "once"
            or type(minimum_timeout_seconds) is not int
            or minimum_timeout_seconds < 0
        ):
            return PreToolCallDirective(
                action="block",
                message="BLOCKED: plugin returned invalid minimum_timeout_seconds",
                modified_args=modified_args,
            )
        if first_approve is None:
            rule_key = result.get("rule_key")
            first_approve = (
                message,
                (rule_key.strip() or None) if isinstance(rule_key, str) else None,
                approval_scope,
                minimum_timeout_seconds,
            )
    if first_approve is None:
        return PreToolCallDirective(modified_args=modified_args)
    return PreToolCallDirective(
        action="approve",
        message=first_approve[0],
        rule_key=first_approve[1],
        approval_scope=first_approve[2],
        minimum_timeout_seconds=first_approve[3],
        modified_args=modified_args,
    )


def resolve_pre_tool_block(
    details: PreToolCallDirective,
    tool_name: str,
    *,
    turn_id: str = "",
    tool_call_id: str = "",
    session_id: str = "",
) -> Optional[str]:
    """Resolve one selected directive through the host approval gate."""
    if details.action == "block":
        return details.message
    if details.action != "approve":
        return None
    try:
        from tools.approval import request_tool_approval
        from tools.approval_context import (
            reset_current_observability_context,
            set_current_observability_context,
        )
        approval_tokens = None
        with suppress(Exception):
            approval_tokens = set_current_observability_context(
                turn_id=turn_id,
                tool_call_id=tool_call_id,
                session_id=session_id,
            )
        try:
            result = request_tool_approval(
                tool_name,
                details.message or "",
                rule_key=details.rule_key or tool_name,
                one_time_only=details.approval_scope == "once",
                minimum_timeout_seconds=details.minimum_timeout_seconds,
            )
        finally:
            if approval_tokens is not None:
                with suppress(Exception):
                    reset_current_observability_context(approval_tokens)
    except Exception:
        logger.exception("Plugin approval gate failed for %s", tool_name)
        return f"BLOCKED: plugin approval gate failed for {tool_name}"
    if not result.get("approved"):
        return str(
            result.get("message")
            or f"BLOCKED: plugin approval required for {tool_name}"
        )
    return None
