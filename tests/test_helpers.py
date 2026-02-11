"""Unit tests for pure helper functions — no Apple Containers needed."""

import pytest

from sandbox_mcp_server import (
    PortForward,
    _format_export_line,
    _humanize_bytes,
    _output_has_token,
    _output_tokens,
    _sq,
    _truncate,
    _validate_env_key,
    SANDBOX_PROFILES,
)


# ── _sq (shell quoting) ─────────────────────────────────────────────────


class TestSq:
    def test_simple_string(self):
        assert _sq("hello") == "'hello'"

    def test_empty_string(self):
        assert _sq("") == "''"

    def test_string_with_spaces(self):
        assert _sq("hello world") == "'hello world'"

    def test_string_with_single_quote(self):
        # 'it'\''s' — shell will concatenate 'it' + \' + 's'
        assert _sq("it's") == "'it'\\''s'"

    def test_string_with_multiple_quotes(self):
        result = _sq("it's a 'test'")
        assert result == "'it'\\''s a '\\''test'\\'''"

    def test_string_with_special_chars(self):
        assert _sq("$HOME") == "'$HOME'"
        assert _sq("`rm -rf /`") == "'`rm -rf /`'"
        assert _sq("$(whoami)") == "'$(whoami)'"

    def test_string_with_semicolon(self):
        assert _sq("foo; rm -rf /") == "'foo; rm -rf /'"

    def test_string_with_newline(self):
        assert _sq("line1\nline2") == "'line1\nline2'"

    def test_path_with_spaces(self):
        assert _sq("/tmp/my dir/file.txt") == "'/tmp/my dir/file.txt'"

    def test_backtick_injection(self):
        result = _sq("file`whoami`.txt")
        assert result == "'file`whoami`.txt'"


# ── _validate_env_key ────────────────────────────────────────────────────


class TestValidateEnvKey:
    def test_simple_key(self):
        assert _validate_env_key("HOME") is True

    def test_underscore_prefix(self):
        assert _validate_env_key("_PRIVATE") is True

    def test_mixed_case(self):
        assert _validate_env_key("myVar123") is True

    def test_empty_string(self):
        assert _validate_env_key("") is False

    def test_starts_with_number(self):
        assert _validate_env_key("1BAD") is False

    def test_has_spaces(self):
        assert _validate_env_key("MY VAR") is False

    def test_has_equals(self):
        assert _validate_env_key("KEY=val") is False

    def test_has_dash(self):
        assert _validate_env_key("my-var") is False

    def test_shell_injection(self):
        assert _validate_env_key("$(whoami)") is False
        assert _validate_env_key("x;rm -rf /") is False
        assert _validate_env_key("KEY`id`") is False

    def test_single_underscore(self):
        assert _validate_env_key("_") is True

    def test_single_letter(self):
        assert _validate_env_key("X") is True


# ── _format_export_line ───────────────────────────────────────────────────


class TestFormatExportLine:
    def test_simple_value(self):
        assert _format_export_line("FOO", "bar") == "export FOO='bar'"

    def test_value_with_spaces(self):
        assert _format_export_line("FOO", "hello world") == "export FOO='hello world'"

    def test_value_with_single_quote(self):
        assert _format_export_line("FOO", "it's") == "export FOO='it'\\''s'"


# ── CLI output tokenization helpers ────────────────────────────────────────


class TestOutputTokenHelpers:
    def test_output_tokens(self):
        out = "NAME TAG SIZE\nmcp-dev latest 123MB\nmcp-snap-prod latest 99MB\n"
        tokens = _output_tokens(out)
        assert "mcp-dev" in tokens
        assert "mcp-snap-prod" in tokens
        assert "SIZE" in tokens

    def test_output_has_token_exact(self):
        out = "mcp-snap-prod-old\n"
        assert _output_has_token(out, "mcp-snap-prod") is False
        assert _output_has_token(out, "mcp-snap-prod-old") is True


# ── _humanize_bytes ──────────────────────────────────────────────────────


class TestHumanizeBytes:
    def test_bytes(self):
        assert _humanize_bytes(0) == "0B"
        assert _humanize_bytes(512) == "512B"
        assert _humanize_bytes(1023) == "1023B"

    def test_kilobytes(self):
        assert _humanize_bytes(1024) == "1.0KB"
        assert _humanize_bytes(1536) == "1.5KB"

    def test_megabytes(self):
        assert _humanize_bytes(1024 * 1024) == "1.0MB"
        assert _humanize_bytes(1024 * 1024 * 5) == "5.0MB"

    def test_gigabytes(self):
        assert _humanize_bytes(1024 * 1024 * 1024) == "1.0GB"
        assert _humanize_bytes(1024 * 1024 * 1024 * 2) == "2.0GB"


# ── _truncate ────────────────────────────────────────────────────────────


class TestTruncate:
    def test_short_text_unchanged(self):
        assert _truncate("hello", limit=100) == "hello"

    def test_long_text_truncated(self):
        text = "x" * 200
        result = _truncate(text, limit=50)
        assert result.startswith("x" * 50)
        assert "[truncated" in result
        assert "total" in result

    def test_exact_limit(self):
        text = "x" * 100
        assert _truncate(text, limit=100) == text


# ── PortForward dataclass ────────────────────────────────────────────────


class TestPortForward:
    def test_creation(self):
        pf = PortForward(host_port=8080, container_port=80, sandbox_name="web")
        assert pf.host_port == 8080
        assert pf.container_port == 80
        assert pf.sandbox_name == "web"
        assert pf._server is None
        assert pf._connections == 0
        assert pf.started_at > 0

    def test_repr_hides_private(self):
        pf = PortForward(host_port=3000, container_port=3000, sandbox_name="default")
        r = repr(pf)
        assert "3000" in r
        assert "default" in r
        # _server and _connections excluded from repr
        assert "_server" not in r
        assert "_connections" not in r

    def test_connection_counter(self):
        pf = PortForward(host_port=5432, container_port=5432, sandbox_name="db")
        pf._connections += 1
        pf._connections += 1
        assert pf._connections == 2


# ── SANDBOX_PROFILES structure ───────────────────────────────────────────


class TestProfiles:
    def test_profiles_is_dict(self):
        assert isinstance(SANDBOX_PROFILES, dict)

    def test_profile_values_are_dicts(self):
        for name, profile in SANDBOX_PROFILES.items():
            assert isinstance(profile, dict), f"Profile '{name}' should be a dict"
