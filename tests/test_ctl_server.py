from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any, cast

import pytest

from sandbox_mcp_server import (
    SandboxCtlServer,
    Sandbox,
)


class FakeManager:
    def __init__(self):
        self._sandboxes: dict[str, Sandbox] = {}
        self._spawn_seqs: dict[str, int] = {}
        self._parent_generations: dict[str, int] = {}
        self._started = True

    async def ensure_started(self):
        pass

    async def _spawn_child(
        self, parent_name="", image="", child_name="", cpus=0, memory=""
    ):
        name = child_name or f"{parent_name}-child-{len(self._sandboxes):04d}"
        sb = Sandbox(
            name=f"mcp-sb-fake-{uuid.uuid4().hex[:6]}", image=image or "mcp-dev"
        )
        sb.role = "child"
        sb.parent = parent_name
        sb.cpus = cpus or 1
        sb.memory_mb = 256
        self._sandboxes[name] = sb
        return sb

    async def destroy_sandbox(self, name, _allow_child=False):
        if name not in self._sandboxes:
            return f"Error: no active sandbox '{name}'"
        del self._sandboxes[name]
        return f"Destroyed sandbox '{name}'"


async def _send_request(
    sock_path: str, method: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    reader, writer = await asyncio.open_unix_connection(sock_path)
    req = {
        "id": uuid.uuid4().hex[:8],
        "method": method,
        "params": params or {},
    }
    writer.write((json.dumps(req) + "\n").encode())
    await writer.drain()
    line = await asyncio.wait_for(reader.readline(), timeout=5)
    writer.close()
    await writer.wait_closed()
    return json.loads(line)


@pytest.fixture
def ctl_sock_dir(monkeypatch):
    import sandbox_mcp_server
    import tempfile

    # Use /tmp directly to stay under macOS sun_path limit (104 bytes)
    sock_dir = tempfile.mkdtemp(prefix="mcp-ctl-test-")
    monkeypatch.setattr(sandbox_mcp_server, "_CTL_SOCK_DIR", sock_dir)
    yield sock_dir
    import shutil

    shutil.rmtree(sock_dir, ignore_errors=True)


class TestCtlServerLifecycle:
    def test_start_creates_socket(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            sock_path = await srv.start_for("test-parent")
            assert os.path.exists(sock_path)
            assert sock_path.endswith("test-parent.sock")
            await srv.stop_all()

        asyncio.run(scenario())

    def test_stop_removes_socket(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            sock_path = await srv.start_for("test-parent")
            assert os.path.exists(sock_path)
            await srv.stop_for("test-parent")
            assert not os.path.exists(sock_path)

        asyncio.run(scenario())

    def test_start_idempotent(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            p1 = await srv.start_for("p")
            p2 = await srv.start_for("p")
            assert p1 == p2
            await srv.stop_all()

        asyncio.run(scenario())

    def test_invalid_parent_name(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            with pytest.raises(ValueError):
                await srv.start_for("bad/name")
            with pytest.raises(ValueError):
                await srv.start_for("")

        asyncio.run(scenario())

    def test_stop_nonexistent_is_noop(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            await srv.stop_for("nonexistent")

        asyncio.run(scenario())


class TestCtlProtocol:
    def test_ping(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            sock_path = await srv.start_for("parent-a")
            try:
                resp = await _send_request(sock_path, "ping")
                assert resp["result"]["ok"]
                assert resp["result"]["parent"] == "parent-a"
            finally:
                await srv.stop_all()

        asyncio.run(scenario())

    def test_spawn(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            sock_path = await srv.start_for("parent-a")
            try:
                resp = await _send_request(
                    sock_path, "spawn", {"image": "mcp-dev", "name": "child-1"}
                )
                assert "error" not in resp
                assert resp["result"]["name"] == "child-1"
                assert resp["result"]["image"] == "mcp-dev"
                assert "child-1" in mgr._sandboxes
            finally:
                await srv.stop_all()

        asyncio.run(scenario())

    def test_list_children(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            sock_path = await srv.start_for("parent-a")
            try:
                await _send_request(sock_path, "spawn", {"name": "c1"})
                await _send_request(sock_path, "spawn", {"name": "c2"})
                resp = await _send_request(sock_path, "list")
                children = resp["result"]["children"]
                names = [c["name"] for c in children]
                assert "c1" in names
                assert "c2" in names
            finally:
                await srv.stop_all()

        asyncio.run(scenario())

    def test_destroy_child(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            sock_path = await srv.start_for("parent-a")
            try:
                await _send_request(sock_path, "spawn", {"name": "target"})
                assert "target" in mgr._sandboxes
                resp = await _send_request(sock_path, "destroy", {"name": "target"})
                assert resp["result"]["ok"]
                assert "target" not in mgr._sandboxes
            finally:
                await srv.stop_all()

        asyncio.run(scenario())

    def test_destroy_wrong_parent(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            sock_a = await srv.start_for("parent-a")
            sock_b = await srv.start_for("parent-b")
            try:
                await _send_request(sock_a, "spawn", {"name": "child-of-a"})
                resp = await _send_request(sock_b, "destroy", {"name": "child-of-a"})
                assert "error" in resp
                assert resp["error"]["code"] == "NOT_FOUND"
            finally:
                await srv.stop_all()

        asyncio.run(scenario())

    def test_unknown_method(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            sock_path = await srv.start_for("parent-a")
            try:
                resp = await _send_request(sock_path, "nonexistent")
                assert "error" in resp
                assert resp["error"]["code"] == "INVALID_REQUEST"
            finally:
                await srv.stop_all()

        asyncio.run(scenario())

    def test_invalid_json(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            sock_path = await srv.start_for("parent-a")
            try:
                reader, writer = await asyncio.open_unix_connection(sock_path)
                writer.write(b"not json\n")
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                writer.close()
                await writer.wait_closed()
                resp = json.loads(line)
                assert "error" in resp
                assert resp["error"]["code"] == "INVALID_REQUEST"
            finally:
                await srv.stop_all()

        asyncio.run(scenario())

    def test_missing_method(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            sock_path = await srv.start_for("parent-a")
            try:
                reader, writer = await asyncio.open_unix_connection(sock_path)
                req = json.dumps({"id": "test"}) + "\n"
                writer.write(req.encode())
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                writer.close()
                await writer.wait_closed()
                resp = json.loads(line)
                assert "error" in resp
                assert resp["error"]["code"] == "INVALID_REQUEST"
            finally:
                await srv.stop_all()

        asyncio.run(scenario())

    def test_concurrent_requests(self, ctl_sock_dir):
        async def scenario():
            mgr = FakeManager()
            srv = SandboxCtlServer(cast(Any, mgr))
            sock_path = await srv.start_for("parent-a")
            try:
                tasks = [_send_request(sock_path, "ping") for _ in range(5)]
                results = await asyncio.gather(*tasks)
                for resp in results:
                    assert resp["result"]["ok"]
            finally:
                await srv.stop_all()

        asyncio.run(scenario())
