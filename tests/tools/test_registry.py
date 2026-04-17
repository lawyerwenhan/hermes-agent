"""Tests for the central tool registry."""

import json

from tools.registry import ToolRegistry


def _dummy_handler(args, **kwargs):
    return json.dumps({"ok": True})


def _make_schema(name="test_tool"):
    return {
        "name": name,
        "description": f"A {name}",
        "parameters": {"type": "object", "properties": {}},
    }


class TestRegisterAndDispatch:
    def test_register_and_dispatch(self):
        reg = ToolRegistry()
        reg.register(
            name="alpha",
            toolset="core",
            schema=_make_schema("alpha"),
            handler=_dummy_handler,
        )
        result = json.loads(reg.dispatch("alpha", {}))
        assert result == {"ok": True}

    def test_dispatch_passes_args(self):
        reg = ToolRegistry()

        def echo_handler(args, **kw):
            return json.dumps(args)

        reg.register(
            name="echo",
            toolset="core",
            schema=_make_schema("echo"),
            handler=echo_handler,
        )
        result = json.loads(reg.dispatch("echo", {"msg": "hi"}))
        assert result == {"msg": "hi"}


class TestGetDefinitions:
    def test_returns_openai_format(self):
        reg = ToolRegistry()
        reg.register(
            name="t1", toolset="s1", schema=_make_schema("t1"), handler=_dummy_handler
        )
        reg.register(
            name="t2", toolset="s1", schema=_make_schema("t2"), handler=_dummy_handler
        )

        defs = reg.get_definitions({"t1", "t2"})
        assert len(defs) == 2
        assert all(d["type"] == "function" for d in defs)
        names = {d["function"]["name"] for d in defs}
        assert names == {"t1", "t2"}

    def test_skips_unavailable_tools(self):
        reg = ToolRegistry()
        reg.register(
            name="available",
            toolset="s",
            schema=_make_schema("available"),
            handler=_dummy_handler,
            check_fn=lambda: True,
        )
        reg.register(
            name="unavailable",
            toolset="s",
            schema=_make_schema("unavailable"),
            handler=_dummy_handler,
            check_fn=lambda: False,
        )
        defs = reg.get_definitions({"available", "unavailable"})
        assert len(defs) == 1
        assert defs[0]["function"]["name"] == "available"

    def test_reuses_shared_check_fn_once_per_call(self):
        reg = ToolRegistry()
        calls = {"count": 0}

        def shared_check():
            calls["count"] += 1
            return True

        reg.register(
            name="first",
            toolset="shared",
            schema=_make_schema("first"),
            handler=_dummy_handler,
            check_fn=shared_check,
        )
        reg.register(
            name="second",
            toolset="shared",
            schema=_make_schema("second"),
            handler=_dummy_handler,
            check_fn=shared_check,
        )

        defs = reg.get_definitions({"first", "second"})
        assert len(defs) == 2
        assert calls["count"] == 1


class TestUnknownToolDispatch:
    def test_returns_error_json(self):
        reg = ToolRegistry()
        result = json.loads(reg.dispatch("nonexistent", {}))
        assert "error" in result
        assert "Unknown tool" in result["error"]


class TestToolsetAvailability:
    def test_no_check_fn_is_available(self):
        reg = ToolRegistry()
        reg.register(
            name="t", toolset="free", schema=_make_schema(), handler=_dummy_handler
        )
        assert reg.is_toolset_available("free") is True

    def test_check_fn_controls_availability(self):
        reg = ToolRegistry()
        reg.register(
            name="t",
            toolset="locked",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: False,
        )
        assert reg.is_toolset_available("locked") is False

    def test_check_toolset_requirements(self):
        reg = ToolRegistry()
        reg.register(
            name="a",
            toolset="ok",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: True,
        )
        reg.register(
            name="b",
            toolset="nope",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: False,
        )

        reqs = reg.check_toolset_requirements()
        assert reqs["ok"] is True
        assert reqs["nope"] is False

    def test_get_all_tool_names(self):
        reg = ToolRegistry()
        reg.register(
            name="z_tool", toolset="s", schema=_make_schema(), handler=_dummy_handler
        )
        reg.register(
            name="a_tool", toolset="s", schema=_make_schema(), handler=_dummy_handler
        )
        assert reg.get_all_tool_names() == ["a_tool", "z_tool"]

    def test_handler_exception_returns_error(self):
        reg = ToolRegistry()

        def bad_handler(args, **kw):
            raise RuntimeError("boom")

        reg.register(
            name="bad", toolset="s", schema=_make_schema(), handler=bad_handler
        )
        result = json.loads(reg.dispatch("bad", {}))
        assert "error" in result
        assert "RuntimeError" in result["error"]


class TestCheckFnExceptionHandling:
    """Verify that a raising check_fn is caught rather than crashing."""

    def test_is_toolset_available_catches_exception(self):
        reg = ToolRegistry()
        reg.register(
            name="t",
            toolset="broken",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: 1 / 0,  # ZeroDivisionError
        )
        # Should return False, not raise
        assert reg.is_toolset_available("broken") is False

    def test_check_toolset_requirements_survives_raising_check(self):
        reg = ToolRegistry()
        reg.register(
            name="a",
            toolset="good",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: True,
        )
        reg.register(
            name="b",
            toolset="bad",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: (_ for _ in ()).throw(ImportError("no module")),
        )

        reqs = reg.check_toolset_requirements()
        assert reqs["good"] is True
        assert reqs["bad"] is False

    def test_get_definitions_skips_raising_check(self):
        reg = ToolRegistry()
        reg.register(
            name="ok_tool",
            toolset="s",
            schema=_make_schema("ok_tool"),
            handler=_dummy_handler,
            check_fn=lambda: True,
        )
        reg.register(
            name="bad_tool",
            toolset="s2",
            schema=_make_schema("bad_tool"),
            handler=_dummy_handler,
            check_fn=lambda: (_ for _ in ()).throw(OSError("network down")),
        )
        defs = reg.get_definitions({"ok_tool", "bad_tool"})
        assert len(defs) == 1
        assert defs[0]["function"]["name"] == "ok_tool"

    def test_check_tool_availability_survives_raising_check(self):
        reg = ToolRegistry()
        reg.register(
            name="a",
            toolset="works",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: True,
        )
        reg.register(
            name="b",
            toolset="crashes",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: 1 / 0,
        )

        available, unavailable = reg.check_tool_availability()
        assert "works" in available
        assert any(u["name"] == "crashes" for u in unavailable)


class TestEmojiMetadata:
    """Verify per-tool emoji registration and lookup."""

    def test_emoji_stored_on_entry(self):
        reg = ToolRegistry()
        reg.register(
            name="t", toolset="s", schema=_make_schema(),
            handler=_dummy_handler, emoji="🔥",
        )
        assert reg._tools["t"].emoji == "🔥"

    def test_get_emoji_returns_registered(self):
        reg = ToolRegistry()
        reg.register(
            name="t", toolset="s", schema=_make_schema(),
            handler=_dummy_handler, emoji="🎯",
        )
        assert reg.get_emoji("t") == "🎯"

    def test_get_emoji_returns_default_when_unset(self):
        reg = ToolRegistry()
        reg.register(
            name="t", toolset="s", schema=_make_schema(),
            handler=_dummy_handler,
        )
        assert reg.get_emoji("t") == "⚡"
        assert reg.get_emoji("t", default="🔧") == "🔧"

    def test_get_emoji_returns_default_for_unknown_tool(self):
        reg = ToolRegistry()
        assert reg.get_emoji("nonexistent") == "⚡"
        assert reg.get_emoji("nonexistent", default="❓") == "❓"

    def test_emoji_empty_string_treated_as_unset(self):
        reg = ToolRegistry()
        reg.register(
            name="t", toolset="s", schema=_make_schema(),
            handler=_dummy_handler, emoji="",
        )
        assert reg.get_emoji("t") == "⚡"


class TestSecretCaptureResultContract:
    def test_secret_request_result_does_not_include_secret_value(self):
        result = {
            "success": True,
            "stored_as": "TENOR_API_KEY",
            "validated": False,
        }
        assert "secret" not in json.dumps(result).lower()


class TestRequiredFieldValidation:
    """Regression for cron 3a3ae5204193 (2026-04-17): the model called
    ``update_issue`` with ``record_issue``-style params (no ``issue_id``),
    which reached the handler lambda and raised ``KeyError: 'issue_id'``.
    Dispatch must now reject missing required fields up-front with a clear,
    model-readable error, not a cryptic KeyError.
    """

    def _schema_with_required(self, name, required):
        props = {r: {"type": "string"} for r in required}
        return {
            "name": name,
            "description": f"A {name}",
            "parameters": {
                "type": "object",
                "properties": props,
                "required": list(required),
            },
        }

    def test_missing_required_returns_clear_error_before_handler(self):
        reg = ToolRegistry()
        calls = {"count": 0}

        def handler(args, **kw):
            calls["count"] += 1
            return json.dumps({"issue_id": args["issue_id"]})  # would KeyError

        reg.register(
            name="update_issue",
            toolset="health",
            schema=self._schema_with_required("update_issue", ["issue_id"]),
            handler=handler,
        )
        # Model forgot issue_id — should short-circuit before handler runs.
        result = json.loads(reg.dispatch("update_issue", {"status": "ESCALATED"}))
        assert "error" in result
        assert "issue_id" in result["error"]
        assert "Missing required parameter" in result["error"]
        assert calls["count"] == 0  # handler was NOT invoked

    def test_all_required_present_runs_handler(self):
        reg = ToolRegistry()
        reg.register(
            name="update_issue",
            toolset="health",
            schema=self._schema_with_required("update_issue", ["issue_id"]),
            handler=lambda args, **kw: json.dumps({"got": args["issue_id"]}),
        )
        result = json.loads(reg.dispatch("update_issue", {"issue_id": "abc123"}))
        assert result == {"got": "abc123"}

    def test_multiple_missing_listed_in_error(self):
        reg = ToolRegistry()
        reg.register(
            name="record_issue",
            toolset="health",
            schema=self._schema_with_required(
                "record_issue",
                ["file_path", "error_type", "severity", "description"],
            ),
            handler=lambda args, **kw: json.dumps({"ok": True}),
        )
        result = json.loads(reg.dispatch("record_issue", {"severity": "HIGH"}))
        assert "error" in result
        # The "Missing required parameter(s) for X: a, b, c." clause
        # must list exactly the absent fields, not the provided one.
        msg = result["error"]
        missing_clause = msg.split("Required:")[0]
        for field in ("file_path", "error_type", "description"):
            assert field in missing_clause
        assert "severity" not in missing_clause  # severity WAS provided

    def test_no_required_list_allows_empty_args(self):
        reg = ToolRegistry()
        reg.register(
            name="query_issues",
            toolset="health",
            schema={
                "name": "query_issues",
                "parameters": {
                    "type": "object",
                    "properties": {"status": {"type": "string"}},
                    "required": [],
                },
            },
            handler=_dummy_handler,
        )
        result = json.loads(reg.dispatch("query_issues", {}))
        assert result == {"ok": True}

    def test_none_args_treated_as_empty(self):
        reg = ToolRegistry()
        reg.register(
            name="update_issue",
            toolset="health",
            schema=self._schema_with_required("update_issue", ["issue_id"]),
            handler=_dummy_handler,
        )
        result = json.loads(reg.dispatch("update_issue", None))
        assert "error" in result
        assert "issue_id" in result["error"]

    def test_null_value_counts_as_present(self):
        """Explicit null is the model's way of clearing a field — don't
        reject it as 'missing'. Required only means the *key* must be sent."""
        reg = ToolRegistry()
        reg.register(
            name="update_issue",
            toolset="health",
            schema=self._schema_with_required("update_issue", ["issue_id"]),
            handler=lambda args, **kw: json.dumps({"issue_id": args["issue_id"]}),
        )
        result = json.loads(reg.dispatch("update_issue", {"issue_id": None}))
        assert result == {"issue_id": None}

    def test_schema_without_parameters_wrapper_supported(self):
        """Tolerate the flat {'required': [...]} variant too."""
        reg = ToolRegistry()
        reg.register(
            name="flat",
            toolset="s",
            schema={"name": "flat", "required": ["x"]},
            handler=_dummy_handler,
        )
        result = json.loads(reg.dispatch("flat", {}))
        assert "error" in result
        assert "x" in result["error"]
