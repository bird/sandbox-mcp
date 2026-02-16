"""Integration tests against real Apple Container VMs.

Requires Apple Silicon Mac with macOS 15+, running container system,
and mcp-dev image. Skipped automatically when unavailable.

Run: uv run pytest tests/test_integration.py -v
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

import pytest

_skip_reason = ""
if not shutil.which("container"):
    _skip_reason = "container CLI not found"
elif sys.platform != "darwin":
    _skip_reason = "Apple Containers requires macOS"
else:
    _r = subprocess.run(
        ["container", "system", "status"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if "running" not in _r.stdout.lower():
        _skip_reason = "container system not running"
    else:
        _r2 = subprocess.run(
            ["container", "image", "list"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if "mcp-dev" not in _r2.stdout:
            _skip_reason = "mcp-dev image not found"

pytestmark = pytest.mark.skipif(bool(_skip_reason), reason=_skip_reason)


def _run(coro):
    return asyncio.run(coro)


async def _with_sandbox(fn):
    import sandbox_mcp_server as s

    fresh = s.SandboxManager()
    old_mgr = s.manager
    s.manager = fresh
    await fresh.ensure_started()
    try:
        await fresh.get_sandbox("default")
        await fn(s)
    finally:
        await fresh.shutdown()
        s.manager = old_mgr


# ── Boot & exec ──────────────────────────────────────────────────────


class TestBootAndExec:
    def test_exec(self):
        async def scenario(s):
            result = await s.exec("echo hello")
            assert "hello" in result

        _run(_with_sandbox(scenario))

    def test_warm_exec_latency(self):
        async def scenario(s):
            await s.exec("true")
            t0 = time.monotonic()
            await s.exec("echo warm")
            elapsed = time.monotonic() - t0
            assert elapsed < 0.5, f"warm exec took {elapsed:.3f}s"

        _run(_with_sandbox(scenario))

    def test_exec_workdir(self):
        async def scenario(s):
            result = await s.exec("pwd", workdir="/tmp")
            assert "/tmp" in result

        _run(_with_sandbox(scenario))

    def test_exec_stdin(self):
        async def scenario(s):
            result = await s.exec("cat", stdin="piped input")
            assert "piped input" in result

        _run(_with_sandbox(scenario))

    def test_exec_exit_code(self):
        async def scenario(s):
            result = await s.exec("exit 42")
            assert "42" in result

        _run(_with_sandbox(scenario))


class TestPython:
    def test_python_exec(self):
        async def scenario(s):
            result = await s.python("print(2 ** 10)")
            assert "1024" in result

        _run(_with_sandbox(scenario))


# ── File operations ──────────────────────────────────────────────────


class TestFileOps:
    def test_write_and_read(self):
        async def scenario(s):
            await s.write_file("/workspace/integ.txt", "integration test")
            content = await s.read_file("/workspace/integ.txt")
            assert "integration test" in content

        _run(_with_sandbox(scenario))

    def test_batch_write(self):
        async def scenario(s):
            files = json.dumps({"/workspace/a.txt": "aaa", "/workspace/b.txt": "bbb"})
            await s.batch_write(files)
            assert "aaa" in await s.read_file("/workspace/a.txt")
            assert "bbb" in await s.read_file("/workspace/b.txt")

        _run(_with_sandbox(scenario))

    def test_upload_and_download(self):
        async def scenario(s):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as f:
                f.write("host content")
                host_path = f.name

            try:
                await s.upload(host_path)
                fname = os.path.basename(host_path)
                content = await s.read_file(f"/workspace/{fname}")
                assert "host content" in content
            finally:
                os.unlink(host_path)

            dl_path = tempfile.mktemp(suffix=".txt")
            try:
                await s.download(f"/workspace/{fname}", dl_path)
                with open(dl_path) as fh:
                    assert "host content" in fh.read()
            finally:
                if os.path.exists(dl_path):
                    os.unlink(dl_path)

        _run(_with_sandbox(scenario))


# ── Env vars ─────────────────────────────────────────────────────────


class TestEnv:
    def test_set_and_list(self):
        async def scenario(s):
            await s.env(action="set", key="INTEG_VAR", value="hello")
            result = await s.env(action="list")
            assert "INTEG_VAR" in result and "hello" in result

        _run(_with_sandbox(scenario))

    def test_env_persists_across_commands(self):
        async def scenario(s):
            await s.env(action="set", key="PERSIST_TEST", value="yes")
            result = await s.exec("echo $PERSIST_TEST")
            assert "yes" in result

        _run(_with_sandbox(scenario))


# ── Package install ──────────────────────────────────────────────────


class TestInstall:
    def test_install_package(self):
        async def scenario(s):
            await s.install("jq")
            result = await s.exec("jq --version")
            assert "jq" in result

        _run(_with_sandbox(scenario))


# ── Background processes ─────────────────────────────────────────────


class TestBgProcesses:
    def test_bg_lifecycle(self):
        async def scenario(s):
            result = await s.bg("sleep 999", name="integ-sleep")
            assert isinstance(result, str)

            logs_result = await s.logs("integ-sleep")
            assert isinstance(logs_result, str)

            kill_result = await s.kill("integ-sleep")
            assert isinstance(kill_result, str)

        _run(_with_sandbox(scenario))


# ── Port forwarding ──────────────────────────────────────────────────


class TestPortForward:
    def test_expose_and_unexpose(self):
        async def scenario(s):
            await s.exec("nohup python3 -m http.server 18765 &>/dev/null &")
            await asyncio.sleep(0.5)

            result = await s.expose(port=18765, host_port=28765)
            assert "28765" in result

            result = await s.unexpose(port=28765)
            assert isinstance(result, str)

        _run(_with_sandbox(scenario))


# ── Status & health ──────────────────────────────────────────────────


class TestObservability:
    def test_stats(self):
        async def scenario(s):
            result = await s.stats()
            assert "default" in result.lower() or "cpu" in result.lower()

        _run(_with_sandbox(scenario))

    def test_health(self):
        async def scenario(s):
            result = await s.health()
            assert "shell=ok" in result or "issue" in result

        _run(_with_sandbox(scenario))

    def test_status(self):
        async def scenario(s):
            result = await s.status()
            assert "default" in result

        _run(_with_sandbox(scenario))

    def test_network_info(self):
        async def scenario(s):
            result = await s.network_info()
            assert "default" in result

        _run(_with_sandbox(scenario))

    def test_history(self):
        async def scenario(s):
            await s.exec("echo history-marker")
            result = await s.history()
            assert "history-marker" in result

        _run(_with_sandbox(scenario))


# ── Snapshot & restore ───────────────────────────────────────────────


class TestSnapshot:
    def test_snapshot_restore_cycle(self):
        async def scenario(s):
            snap_name = "integ-snap-test"
            try:
                await s.write_file("/workspace/snap.txt", "before-snap")
                await s.snapshot(snap_name)

                result = await s.list_snapshots()
                assert snap_name in result

                await s.restore(snap_name)
                result = await s.exec("echo post-restore")
                assert "post-restore" in result
            finally:
                try:
                    await s.delete_snapshot(snap_name)
                except Exception:
                    pass

        _run(_with_sandbox(scenario))


# ── Reset ────────────────────────────────────────────────────────────


class TestReset:
    def test_reset_wipes_workspace(self):
        async def scenario(s):
            await s.exec("touch /workspace/before-reset.txt")
            await s.reset(wipe_workspace=True)
            result = await s.exec(
                "test -f /workspace/before-reset.txt && echo exists || echo gone"
            )
            assert "gone" in result

        _run(_with_sandbox(scenario))
