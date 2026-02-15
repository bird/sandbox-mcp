from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import pytest

import sandbox_mcp_server as sm

from tests.conftest import _configure_module, _make_spawn_policy, _manager


class TestParseMemoryMb:
    @pytest.mark.parametrize(
        ("mem", "expected"),
        [
            ("512M", 512),
            ("1G", 1024),
            ("2048M", 2048),
            ("256m", 256),
            ("1g", 1024),
        ],
    )
    def test_valid(self, mem: str, expected: int):
        assert sm._parse_memory_mb(mem) == expected

    @pytest.mark.parametrize("mem", ["", "512", "1T", "hello", None])
    def test_invalid_raises(self, mem):
        with pytest.raises(ValueError):
            sm._parse_memory_mb(mem)


class TestSandboxDataclass:
    def test_defaults(self):
        sb = sm.Sandbox(name="mcp-sb-x", image="mcp-dev")
        assert sb.role == "primary"
        assert sb.parent is None
        assert sb.expires_at is None
        assert sb.cpus == sm.SANDBOX_CPUS
        assert sb.memory_mb == sm._parse_memory_mb(sm.SANDBOX_MEMORY)


class TestComputeVisiblePeers:
    def _mk(self, role: str, parent: str | None = None) -> sm.Sandbox:
        sb = sm.Sandbox(
            name=f"mcp-sb-{role}-{int(time.time() * 1000)}", image="mcp-dev"
        )
        sb.role = role
        sb.parent = parent
        return sb

    def test_family_mode(self, monkeypatch: pytest.MonkeyPatch):
        mgr = sm.SandboxManager()
        mgr._sandboxes = {
            "parent": self._mk("primary"),
            "child-a": self._mk("child", parent="parent"),
            "child-b": self._mk("child", parent="parent"),
            "outsider": self._mk("primary"),
        }
        all_entries = {
            name: f"192.168.0.{i}" for i, name in enumerate(mgr._sandboxes, 10)
        }

        monkeypatch.setattr(
            sm, "SPAWN_POLICIES", {"parent": {"child_network_peers": "family"}}
        )

        parent_visible = mgr._compute_visible_peers(
            "parent", mgr._sandboxes["parent"], all_entries
        )
        assert parent_visible == {"child-a", "child-b", "outsider"}

        child_visible = mgr._compute_visible_peers(
            "child-a", mgr._sandboxes["child-a"], all_entries
        )
        assert child_visible == {"parent", "child-b"}

        outsider_visible = mgr._compute_visible_peers(
            "outsider", mgr._sandboxes["outsider"], all_entries
        )
        assert outsider_visible == {"parent", "child-a", "child-b"}

    def test_all_mode(self, monkeypatch: pytest.MonkeyPatch):
        mgr = sm.SandboxManager()
        mgr._sandboxes = {
            "parent": self._mk("primary"),
            "child-a": self._mk("child", parent="parent"),
            "child-b": self._mk("child", parent="parent"),
            "outsider": self._mk("primary"),
        }
        all_entries = {
            name: f"192.168.0.{i}" for i, name in enumerate(mgr._sandboxes, 10)
        }

        monkeypatch.setattr(
            sm, "SPAWN_POLICIES", {"parent": {"child_network_peers": "all"}}
        )

        assert mgr._compute_visible_peers(
            "parent", mgr._sandboxes["parent"], all_entries
        ) == {"child-a", "child-b", "outsider"}
        assert mgr._compute_visible_peers(
            "child-a", mgr._sandboxes["child-a"], all_entries
        ) == {"parent", "child-b", "outsider"}
        assert mgr._compute_visible_peers(
            "outsider", mgr._sandboxes["outsider"], all_entries
        ) == {"parent", "child-a", "child-b"}

    def test_none_mode(self, monkeypatch: pytest.MonkeyPatch):
        mgr = sm.SandboxManager()
        mgr._sandboxes = {
            "parent": self._mk("primary"),
            "child-a": self._mk("child", parent="parent"),
            "child-b": self._mk("child", parent="parent"),
            "outsider": self._mk("primary"),
        }
        all_entries = {
            name: f"192.168.0.{i}" for i, name in enumerate(mgr._sandboxes, 10)
        }

        monkeypatch.setattr(
            sm, "SPAWN_POLICIES", {"parent": {"child_network_peers": "none"}}
        )

        assert (
            mgr._compute_visible_peers(
                "child-a", mgr._sandboxes["child-a"], all_entries
            )
            == set()
        )
        assert mgr._compute_visible_peers(
            "parent", mgr._sandboxes["parent"], all_entries
        ) == {"outsider"}
        assert mgr._compute_visible_peers(
            "outsider", mgr._sandboxes["outsider"], all_entries
        ) == {"parent", "child-a", "child-b"}

    def test_no_spawn_policy_backward_compatible(self, monkeypatch: pytest.MonkeyPatch):
        mgr = sm.SandboxManager()
        mgr._sandboxes = {
            "legacy-parent": self._mk("primary"),
            "legacy-child": self._mk("child", parent="legacy-parent"),
            "outsider": self._mk("primary"),
        }
        all_entries = {
            name: f"192.168.1.{i}" for i, name in enumerate(mgr._sandboxes, 10)
        }

        monkeypatch.setattr(sm, "SPAWN_POLICIES", {})

        assert mgr._compute_visible_peers(
            "legacy-child", mgr._sandboxes["legacy-child"], all_entries
        ) == {"legacy-parent", "outsider"}


class TestStateV2Format:
    def test_save_state_v2_schema_and_atomic_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        state_file = tmp_path / "state" / "state.json"
        monkeypatch.setattr(sm, "STATE_FILE", str(state_file))

        calls: list[tuple[str, str]] = []
        orig_replace = sm.os.replace

        def _replace(src: str, dst: str):
            calls.append((src, dst))
            return orig_replace(src, dst)

        monkeypatch.setattr(sm.os, "replace", _replace)

        mgr = sm.SandboxManager()
        parent = sm.Sandbox(
            name="mcp-sb-parent",
            image="mcp-dev",
            created_at=1000.0,
            cpus=2,
            memory_mb=512,
        )
        parent.role = "primary"
        child = sm.Sandbox(
            name="mcp-sb-child",
            image="mcp-dev",
            role="child",
            parent="parent",
            parent_generation=7,
            created_at=1001.0,
            expires_at=2000.0,
            cpus=1,
            memory_mb=256,
        )

        mgr._sandboxes = {"parent": parent, "child": child}
        mgr._spawn_seqs = {"parent": 3}
        mgr._parent_generations = {"parent": 7}

        mgr._save_state()
        assert state_file.exists()
        assert calls and calls[-1][1] == str(state_file)
        assert calls[-1][0].endswith(".tmp")
        assert not os.path.exists(calls[-1][0])

        raw = json.loads(state_file.read_text())
        assert raw["schema_version"] == 2
        assert raw["spawn_seqs"] == {"parent": 3}
        assert raw["parent_generations"] == {"parent": 7}
        assert isinstance(raw["sandboxes"], dict)

        p = raw["sandboxes"]["parent"]
        assert p["container"] == "mcp-sb-parent"
        assert p["image"] == "mcp-dev"
        assert p["role"] == "primary"
        assert p["parent"] is None
        assert p["created_at"] == 1000.0
        assert p["expires_at"] is None
        assert p["cpus"] == 2
        assert p["memory_mb"] == 512
        assert p["spawn_seq"] == 3
        assert p["generation"] == 0

        c = raw["sandboxes"]["child"]
        assert c["container"] == "mcp-sb-child"
        assert c["role"] == "child"
        assert c["parent"] == "parent"
        assert c["expires_at"] == 2000.0
        assert c["cpus"] == 1
        assert c["memory_mb"] == 256
        assert c["parent_generation"] == 7

    def test_load_state_v1_to_v2_migration(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        state_file = tmp_path / "state" / "state.json"
        state_file.parent.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(sm, "STATE_FILE", str(state_file))

        v1 = {
            "legacy": {
                "container": "mcp-sb-legacy",
                "image": "mcp-dev",
                "created_at": 123.0,
            }
        }
        state_file.write_text(json.dumps(v1))

        mgr = sm.SandboxManager()
        migrated = mgr._load_state()

        assert migrated["schema_version"] == 2
        assert migrated["spawn_seqs"] == {}
        assert migrated["parent_generations"] == {}
        assert "sandboxes" in migrated
        assert "legacy" in migrated["sandboxes"]

        info = migrated["sandboxes"]["legacy"]
        assert info["container"] == "mcp-sb-legacy"
        assert info["image"] == "mcp-dev"
        assert info["role"] == "primary"
        assert info["parent"] is None
        assert info["expires_at"] is None
        assert info["cpus"] == sm.SANDBOX_CPUS
        assert info["memory_mb"] == sm._parse_memory_mb(sm.SANDBOX_MEMORY)


def test_spawn_child_policy_enforcement(
    mock_container_cli, monkeypatch: pytest.MonkeyPatch
):
    import sandbox_mcp_server as smi

    _configure_module(smi, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(smi) as mgr:
            monkeypatch.setattr(smi, "manager", mgr)
            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "parent-test": _make_spawn_policy(
                        max_concurrent=2,
                        max_total=5,
                        child_ttl=1,
                    )
                },
            )

            await mgr.get_sandbox("parent-test")

            child = await mgr._spawn_child(
                parent_name="parent-test",
                image="mcp-dev",
                cpus=99,
                memory="9999M",
            )
            assert child.role == "child"
            assert child.parent == "parent-test"
            assert child.cpus == 2
            assert child.memory_mb == 512
            assert child.expires_at is not None
            assert int(child.expires_at - child.created_at) == 1

            child_name = next(n for n, s in mgr._sandboxes.items() if s is child)

            with pytest.raises(PermissionError):
                await mgr._spawn_child(parent_name=child_name, image="mcp-dev")

            with pytest.raises(PermissionError):
                await mgr._spawn_child(parent_name="parent-test", image="not-allowed")

            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "parent-test": _make_spawn_policy(
                        max_concurrent=2,
                        max_total=5,
                        allowed_images=[],
                    )
                },
            )
            with pytest.raises(PermissionError):
                await mgr._spawn_child(parent_name="parent-test")

            monkeypatch.setattr(smi, "SPAWN_POLICIES", {})
            with pytest.raises(PermissionError):
                await mgr._spawn_child(parent_name="parent-test", image="mcp-dev")

            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "parent-test": _make_spawn_policy(
                        max_concurrent=10,
                        max_total=2,
                    )
                },
            )
            await mgr._destroy_children("parent-test")
            mgr._spawn_seqs["parent-test"] = 0

            with pytest.raises(ValueError):
                await mgr._spawn_child(parent_name="parent-test", cpus=-1)
            with pytest.raises(ValueError):
                await mgr._spawn_child(parent_name="parent-test", memory="32M")

            await mgr._spawn_child(parent_name="parent-test")
            await mgr._spawn_child(parent_name="parent-test")
            with pytest.raises(RuntimeError):
                await mgr._spawn_child(parent_name="parent-test")

            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {"parent-test": _make_spawn_policy(max_concurrent=1)},
            )
            await mgr._destroy_children("parent-test")

            await mgr._spawn_child(parent_name="parent-test")
            with pytest.raises(RuntimeError):
                await mgr._spawn_child(parent_name="parent-test")

    asyncio.run(scenario())


def test_spawn_child_resource_accounting(
    mock_container_cli, monkeypatch: pytest.MonkeyPatch
):
    import sandbox_mcp_server as smi

    _configure_module(smi, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(smi) as mgr:
            monkeypatch.setattr(smi, "manager", mgr)
            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "parent-budget": _make_spawn_policy(
                        max_concurrent=10,
                        total_child_cpus=4,
                        total_child_memory_mb=1024,
                    )
                },
            )

            await mgr.get_sandbox("parent-budget")

            await mgr._spawn_child(parent_name="parent-budget", cpus=2, memory="512M")
            await mgr._spawn_child(parent_name="parent-budget", cpus=2, memory="512M")

            with pytest.raises(RuntimeError):
                await mgr._spawn_child(
                    parent_name="parent-budget", cpus=1, memory="64M"
                )

            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "parent-budget": _make_spawn_policy(
                        max_concurrent=10,
                        total_child_cpus=100,
                        total_child_memory_mb=600,
                    )
                },
            )
            await mgr._destroy_children("parent-budget")
            mgr._spawn_seqs["parent-budget"] = 0

            await mgr._spawn_child(parent_name="parent-budget", cpus=1, memory="512M")
            with pytest.raises(RuntimeError):
                await mgr._spawn_child(
                    parent_name="parent-budget", cpus=1, memory="512M"
                )

    asyncio.run(scenario())


def test_cascade_destroy(mock_container_cli, monkeypatch: pytest.MonkeyPatch):
    import sandbox_mcp_server as smi

    _configure_module(smi, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(smi) as mgr:
            monkeypatch.setattr(smi, "manager", mgr)
            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "parent-cascade": _make_spawn_policy(
                        total_child_cpus=6,
                        total_child_memory_mb=2048,
                    )
                },
            )

            await mgr.get_sandbox("parent-cascade")
            c1 = await mgr._spawn_child(parent_name="parent-cascade")
            c2 = await mgr._spawn_child(parent_name="parent-cascade")
            c1_name = next(n for n, s in mgr._sandboxes.items() if s is c1)
            c2_name = next(n for n, s in mgr._sandboxes.items() if s is c2)

            await mgr.destroy_sandbox("parent-cascade")
            assert "parent-cascade" not in mgr._sandboxes
            assert c1_name not in mgr._sandboxes
            assert c2_name not in mgr._sandboxes

    asyncio.run(scenario())


def test_cascade_on_reset(mock_container_cli, monkeypatch: pytest.MonkeyPatch):
    import sandbox_mcp_server as smi

    _configure_module(smi, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(smi) as mgr:
            monkeypatch.setattr(smi, "manager", mgr)
            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "parent-reset": _make_spawn_policy(
                        total_child_cpus=6,
                        total_child_memory_mb=2048,
                    )
                },
            )

            sb = await mgr.get_sandbox("parent-reset")
            before = sb.name
            child = await mgr._spawn_child(parent_name="parent-reset")
            child_name = next(n for n, s in mgr._sandboxes.items() if s is child)

            msg = await mgr.reset(name="parent-reset", wipe_workspace=False)
            assert "Fresh sandbox 'parent-reset' ready" in msg
            assert child_name not in mgr._sandboxes
            assert mgr._parent_generations.get("parent-reset", 0) == 1

            after = mgr._sandboxes["parent-reset"].name
            assert before != after

    asyncio.run(scenario())


def test_child_tool_restrictions(mock_container_cli, monkeypatch: pytest.MonkeyPatch):
    import sandbox_mcp_server as smi

    _configure_module(smi, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(smi) as mgr:
            monkeypatch.setattr(smi, "manager", mgr)
            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "parent-tools": _make_spawn_policy(
                        max_concurrent=2,
                        max_total=5,
                        total_child_cpus=4,
                        total_child_memory_mb=1024,
                    )
                },
            )

            await mgr.get_sandbox("parent-tools")
            child = await mgr._spawn_child(parent_name="parent-tools")
            child_name = next(n for n, s in mgr._sandboxes.items() if s is child)

            snap = await smi.snapshot(snapshot_name="x", sandbox=child_name)
            assert "Error: snapshots not permitted on child sandboxes" in snap

            reset = await smi.reset(wipe_workspace=False, sandbox=child_name)
            assert "Error: reset not permitted on child sandboxes" in reset

            clone = await smi.clone(source=child_name, target="x")
            assert "Error: cloning from a child sandbox is not permitted" in clone

    asyncio.run(scenario())


def test_spawn_tools_roundtrip(mock_container_cli, monkeypatch: pytest.MonkeyPatch):
    import sandbox_mcp_server as smi

    _configure_module(smi, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(smi) as mgr:
            monkeypatch.setattr(smi, "manager", mgr)
            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "parent-roundtrip": _make_spawn_policy(
                        max_concurrent=2,
                        max_total=5,
                        total_child_cpus=4,
                        total_child_memory_mb=1024,
                    )
                },
            )

            await mgr.get_sandbox("parent-roundtrip")

            out = await smi.spawn(parent="parent-roundtrip")
            assert out.startswith("Spawned child '")
            child_name = out.split("Spawned child '", 1)[1].split("'", 1)[0]
            assert child_name in mgr._sandboxes

            listing = await smi.children(parent="parent-roundtrip")
            assert "Children of 'parent-roundtrip'" in listing
            assert child_name in listing

            destroyed = await smi.destroy_child(name=child_name)
            assert f"Destroyed sandbox '{child_name}'" in destroyed
            assert child_name not in mgr._sandboxes

            listing_after = await smi.children(parent="parent-roundtrip")
            assert "No active children for 'parent-roundtrip'" in listing_after

    asyncio.run(scenario())


def test_grandchild_spawning(mock_container_cli, monkeypatch: pytest.MonkeyPatch):
    import sandbox_mcp_server as smi

    _configure_module(smi, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(smi) as mgr:
            monkeypatch.setattr(smi, "manager", mgr)
            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "root": _make_spawn_policy(
                        max_concurrent=10,
                        max_total=10,
                        total_child_cpus=6,
                        total_child_memory_mb=2048,
                        child_max_cpus=2,
                        child_max_memory="512M",
                        child_can_spawn=True,
                        inject_ctl=False,
                    )
                },
            )

            await mgr.get_sandbox("root")
            c1 = await mgr._spawn_child(
                parent_name="root",
                child_name="kid-a",
                cpus=2,
                memory="512M",
            )
            c2 = await mgr._spawn_child(
                parent_name="root",
                child_name="kid-b",
                cpus=2,
                memory="512M",
            )
            assert c1.generation == 1
            assert c2.generation == 1
            assert "kid-a" in mgr._derived_policies

            grandchild = await mgr._spawn_child(
                parent_name="kid-a",
                child_name="gkid-1",
                cpus=2,
                memory="512M",
            )
            assert grandchild.generation == 2
            assert grandchild.parent == "kid-a"

            with pytest.raises(PermissionError, match="max spawn depth"):
                await mgr._spawn_child(parent_name="gkid-1", child_name="nope")

            with pytest.raises(smi.SpawnLimitError, match="CPU budget exceeded"):
                await mgr._spawn_child(
                    parent_name="kid-a",
                    child_name="gkid-2",
                    cpus=1,
                    memory="512M",
                )

    asyncio.run(scenario())


def test_root_budget_includes_grandchildren(
    mock_container_cli, monkeypatch: pytest.MonkeyPatch
):
    """Root spawning a direct child must account for grandchildren already using budget."""
    import sandbox_mcp_server as smi

    _configure_module(smi, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(smi) as mgr:
            monkeypatch.setattr(smi, "manager", mgr)
            # total_child_cpus=4: enough for kid-a(2) + gkid(1) = 3, but not +2 more
            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "root": _make_spawn_policy(
                        max_concurrent=10,
                        max_total=10,
                        total_child_cpus=4,
                        total_child_memory_mb=2048,
                        child_max_cpus=2,
                        child_max_memory="512M",
                        child_can_spawn=True,
                        inject_ctl=False,
                    )
                },
            )

            await mgr.get_sandbox("root")
            await mgr._spawn_child(
                parent_name="root", child_name="kid-a", cpus=2, memory="512M"
            )
            await mgr._spawn_child(
                parent_name="kid-a", child_name="gkid", cpus=1, memory="256M"
            )

            # kid-a(2) + gkid(1) = 3 used. Root's local check only sees kid-a(2),
            # so without tree-wide accounting this would incorrectly pass.
            with pytest.raises(smi.SpawnLimitError, match="CPU budget exceeded"):
                await mgr._spawn_child(
                    parent_name="root", child_name="kid-b", cpus=2, memory="256M"
                )

    asyncio.run(scenario())


def test_inject_ctl_false(mock_container_cli, monkeypatch: pytest.MonkeyPatch):
    import sandbox_mcp_server as smi

    _configure_module(smi, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(smi) as mgr:
            monkeypatch.setattr(smi, "manager", mgr)
            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {"noctl": _make_spawn_policy(inject_ctl=False)},
            )

            await mgr.get_sandbox("noctl")
            assert "noctl" not in mgr._ctl_server._listeners

    asyncio.run(scenario())


def test_generation_depth_limit(mock_container_cli, monkeypatch: pytest.MonkeyPatch):
    import sandbox_mcp_server as smi

    _configure_module(smi, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(smi) as mgr:
            monkeypatch.setattr(smi, "manager", mgr)
            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {"root": _make_spawn_policy(child_can_spawn=True, inject_ctl=False)},
            )

            await mgr.get_sandbox("root")
            await mgr._spawn_child(parent_name="root", child_name="kid")
            await mgr._spawn_child(parent_name="kid", child_name="gkid")

            with pytest.raises(PermissionError, match="max spawn depth"):
                await mgr._spawn_child(parent_name="gkid", child_name="too-deep")

    asyncio.run(scenario())


def test_derived_policy_values(mock_container_cli, monkeypatch: pytest.MonkeyPatch):
    import sandbox_mcp_server as smi

    _configure_module(smi, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(smi) as mgr:
            monkeypatch.setattr(smi, "manager", mgr)
            monkeypatch.setattr(
                smi,
                "SPAWN_POLICIES",
                {
                    "p": _make_spawn_policy(
                        max_concurrent=4,
                        max_total=8,
                        total_child_cpus=6,
                        total_child_memory_mb=2048,
                        child_ttl=600,
                        child_can_spawn=True,
                        inject_ctl=False,
                    )
                },
            )

            await mgr.get_sandbox("p")
            await mgr._spawn_child(parent_name="p", child_name="c")

            d = mgr._derived_policies["c"]
            assert d["max_concurrent"] == 2
            assert d["max_total"] == 4
            assert d["total_child_cpus"] == 3
            assert d["total_child_memory_mb"] == 1024
            assert d["child_can_spawn"] is False
            assert d["inject_ctl"] is False
            assert d["allowed_images"] == ["mcp-dev"]
            assert d["child_ttl"] <= 600

    asyncio.run(scenario())
