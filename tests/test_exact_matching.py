"""Exact-token matching tests for CLI output parsing."""

from __future__ import annotations

import asyncio
from pathlib import Path


def test_check_image_uses_exact_token_match(monkeypatch):
    import sandbox_mcp_server as sm

    async def fake_run(cmd, timeout=30.0, input_data=None):
        if cmd[:3] == ["container", "image", "ls"]:
            return 0, "mcp-dev-old\n", ""
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(sm, "_run", fake_run)
    mgr = sm.SandboxManager(image="mcp-dev")
    assert asyncio.run(mgr.check_image()) is False


def test_restore_rejects_prefix_only_snapshot_match(monkeypatch):
    import sandbox_mcp_server as sm

    async def fake_run(cmd, timeout=30.0, input_data=None):
        if cmd[:3] == ["container", "image", "ls"]:
            return 0, "mcp-snap-prod-old\n", ""
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(sm, "_run", fake_run)
    mgr = sm.SandboxManager()
    msg = asyncio.run(mgr.restore("prod", sandbox_name="default"))
    assert "not found" in msg


def test_ensure_sandbox_volumes_requires_exact_names(monkeypatch):
    import sandbox_mcp_server as sm

    created: list[str] = []

    async def fake_run(cmd, timeout=30.0, input_data=None):
        if cmd[:3] == ["container", "volume", "ls"]:
            return 0, "mcp-workspace-prod-old\nmcp-cache-apk-prod-old\n", ""
        if cmd[:3] == ["container", "volume", "create"]:
            created.append(cmd[3])
            return 0, cmd[3], ""
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(sm, "_run", fake_run)
    mounts = asyncio.run(sm._ensure_sandbox_volumes("prod"))
    assert mounts["workspace"] == "mcp-workspace-prod"
    assert "mcp-workspace-prod" in created
    assert "mcp-cache-apk-prod" in created


def test_cleanup_orphans_skips_without_saved_state(monkeypatch, tmp_path: Path):
    import sandbox_mcp_server as sm

    calls = {"count": 0}

    async def fake_run(cmd, timeout=30.0, input_data=None):
        calls["count"] += 1
        return 0, "", ""

    monkeypatch.setattr(sm, "_run", fake_run)
    monkeypatch.setattr(sm, "STATE_FILE", str(tmp_path / "missing-state.json"))

    asyncio.run(sm._cleanup_orphans())
    assert calls["count"] == 0


def test_cleanup_orphans_skips_with_corrupt_state(monkeypatch, tmp_path: Path):
    import sandbox_mcp_server as sm

    state_file = tmp_path / "state.json"
    state_file.write_text("{not-json")
    calls = {"count": 0}

    async def fake_run(cmd, timeout=30.0, input_data=None):
        calls["count"] += 1
        return 0, "", ""

    monkeypatch.setattr(sm, "_run", fake_run)
    monkeypatch.setattr(sm, "STATE_FILE", str(state_file))

    asyncio.run(sm._cleanup_orphans())
    assert calls["count"] == 0
