"""Tests for the permission_level system in tools.registry."""

import pytest
from tools.registry import registry, ToolEntry

# Ensure all tool modules are imported so their register() calls fire.
from model_tools import _discover_tools
_discover_tools()


class TestToolEntryPermissionLevel:
    """Test ToolEntry.permission_level field."""

    def test_default_permission_is_write(self):
        """Unspecified permission_level defaults to 'write'."""
        entry = ToolEntry(
            name="test_tool",
            toolset="test",
            schema={"name": "test_tool", "description": "", "parameters": {}},
            handler=lambda args, **kw: "{}",
            check_fn=None,
            requires_env=[],
            is_async=False,
            description="test",
            emoji="🔧",
        )
        assert entry.permission_level == "write"

    def test_explicit_permission_read(self):
        """permission_level='read' is stored correctly."""
        entry = ToolEntry(
            name="test_tool",
            toolset="test",
            schema={"name": "test_tool", "description": "", "parameters": {}},
            handler=lambda args, **kw: "{}",
            check_fn=None,
            requires_env=[],
            is_async=False,
            description="test",
            emoji="🔧",
            permission_level="read",
        )
        assert entry.permission_level == "read"

    def test_explicit_permission_dangerous(self):
        """permission_level='dangerous' is stored correctly."""
        entry = ToolEntry(
            name="test_tool",
            toolset="test",
            schema={"name": "test_tool", "description": "", "parameters": {}},
            handler=lambda args, **kw: "{}",
            check_fn=None,
            requires_env=[],
            is_async=False,
            description="test",
            emoji="🔧",
            permission_level="dangerous",
        )
        assert entry.permission_level == "dangerous"

    def test_none_permission_defaults_to_write(self):
        """permission_level=None falls back to 'write'."""
        entry = ToolEntry(
            name="test_tool",
            toolset="test",
            schema={"name": "test_tool", "description": "", "parameters": {}},
            handler=lambda args, **kw: "{}",
            check_fn=None,
            requires_env=[],
            is_async=False,
            description="test",
            emoji="🔧",
            permission_level=None,
        )
        assert entry.permission_level == "write"


class TestRegistryPermissionQueries:
    """Test registry methods for querying permission levels."""

    def test_get_permission_level_known_tool(self):
        """get_permission_level returns correct level for registered tools."""
        # These tools are known to be registered with specific permission levels
        assert registry.get_permission_level("read_file") == "read"
        assert registry.get_permission_level("web_search") == "read"
        assert registry.get_permission_level("write_file") == "write"
        assert registry.get_permission_level("terminal") == "dangerous"

    def test_get_permission_level_unknown_tool(self):
        """get_permission_level returns 'write' for unknown tools."""
        assert registry.get_permission_level("nonexistent_tool_xyz") == "write"

    def test_get_tools_by_permission_read(self):
        """get_tools_by_permission('read') returns only read-only tools."""
        read_tools = registry.get_tools_by_permission("read")
        assert "read_file" in read_tools
        assert "web_search" in read_tools
        assert "session_search" in read_tools
        # Write tools should NOT be in read list
        assert "write_file" not in read_tools
        assert "terminal" not in read_tools

    def test_get_tools_by_permission_dangerous(self):
        """get_tools_by_permission('dangerous') returns only dangerous tools."""
        dangerous_tools = registry.get_tools_by_permission("dangerous")
        assert "terminal" in dangerous_tools
        # Read tools should NOT be in dangerous list
        assert "read_file" not in dangerous_tools

    def test_get_tools_by_permission_write(self):
        """get_tools_by_permission('write') returns write-level tools."""
        write_tools = registry.get_tools_by_permission("write")
        assert "write_file" in write_tools
        assert "memory" in write_tools
        # Read and dangerous tools should NOT be in write list
        assert "read_file" not in write_tools
        assert "terminal" not in write_tools

    def test_all_tools_have_permission_level(self):
        """Every registered tool has a valid permission_level."""
        valid_levels = {"read", "write", "dangerous"}
        for name in registry.get_all_tool_names():
            entry = registry._tools.get(name)
            assert entry is not None, f"Tool {name} has no registry entry"
            assert entry.permission_level in valid_levels, \
                f"Tool {name} has invalid permission_level: {entry.permission_level}"

    def test_read_tools_are_parallel_safe(self):
        """All read-level tools should be in the parallel-safe set."""
        from run_agent import _get_parallel_safe_tools
        safe = _get_parallel_safe_tools()
        read_tools = registry.get_tools_by_permission("read")
        for tool in read_tools:
            assert tool in safe, f"Read tool {tool} not in parallel-safe set"


class TestParallelSafeDynamic:
    """Test that _get_parallel_safe_tools dynamically reads from registry."""

    def test_dynamic_equals_static_plus_registry_reads(self):
        """Dynamic set should include static fallback tools plus registry read tools."""
        from run_agent import _get_parallel_safe_tools, _STATIC_PARALLEL_SAFE_TOOLS
        safe = _get_parallel_safe_tools()
        # Dynamic should include everything from the static set
        for tool in _STATIC_PARALLEL_SAFE_TOOLS:
            assert tool in safe, f"Static tool {tool} missing from dynamic set"

    def test_dynamic_includes_all_registered_reads(self):
        """Dynamic set should include all tools with permission_level='read'."""
        from run_agent import _get_parallel_safe_tools
        safe = _get_parallel_safe_tools()
        read_tools = registry.get_tools_by_permission("read")
        for tool in read_tools:
            assert tool in safe, f"Read tool {tool} not in dynamic parallel-safe set"