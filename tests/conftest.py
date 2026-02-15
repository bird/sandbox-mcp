from __future__ import annotations

import contextlib
import os
from pathlib import Path

import pytest


def _configure_module(
    sm_mod, monkeypatch: pytest.MonkeyPatch, paths: dict[str, Path]
) -> None:
    state_file = paths["home_dir"] / ".local" / "state" / "sandbox-mcp" / "state.json"
    env_file = paths["tmp_path"] / "mcp-env.sh"
    monkeypatch.setattr(sm_mod, "STATE_FILE", str(state_file))
    monkeypatch.setattr(sm_mod, "ENV_FILE", str(env_file))
    monkeypatch.setattr(sm_mod, "_CTL_BINARY", "/nonexistent/sandbox-ctl")

    async def _no_warm_boot(self):
        return None

    monkeypatch.setattr(sm_mod.SandboxManager, "_warm_boot", _no_warm_boot)


def _make_spawn_policy(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "max_concurrent": 3,
        "max_total": 10,
        "total_child_cpus": 8,
        "total_child_memory_mb": 4096,
        "child_max_cpus": 2,
        "child_max_memory": "512M",
        "allowed_images": ["mcp-dev"],
        "child_ttl": 0,
        "child_can_spawn": False,
        "child_network_peers": "family",
        "child_can_be_cloned": False,
        "child_can_be_snapshotted": False,
        "child_allow_port_forward": False,
        "inject_ctl": True,
    }
    base.update(overrides)
    return base


@contextlib.asynccontextmanager
async def _manager(sm_mod):
    mgr = sm_mod.SandboxManager()
    try:
        yield mgr
    finally:
        await mgr.shutdown()


_FAKE_CONTAINER_SCRIPT = """#!/usr/bin/env python3
import json
import os
import subprocess
import sys


STATE_PATH = os.environ.get("FAKE_CONTAINER_STATE")
if not STATE_PATH:
    print("FAKE_CONTAINER_STATE is required", file=sys.stderr)
    sys.exit(2)


def load_state():
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH) as f:
            return json.load(f)
    return {"containers": {}, "volumes": [], "images": ["mcp-dev"]}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f)


def die(msg, code=1):
    print(msg, file=sys.stderr)
    sys.exit(code)


def handle_run(args, state):
    name = None
    image = None
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in ("-d", "--virtualization"):
            i += 1
            continue
        if tok in ("--name", "--cpus", "--memory", "--volume"):
            if i + 1 >= len(args):
                die(f"missing value for {tok}")
            if tok == "--name":
                name = args[i + 1]
            i += 2
            continue
        image = tok
        break
    if not name or not image:
        die("invalid run command")
    state["containers"][name] = {"image": image, "running": True}
    save_state(state)
    print(name)
    return 0


def handle_exec(args, state):
    interactive = False
    workdir = None
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "-i":
            interactive = True
            i += 1
            continue
        if tok == "-w":
            if i + 1 >= len(args):
                die("missing -w value")
            workdir = args[i + 1]
            i += 2
            continue
        break

    if i >= len(args):
        die("missing container name")
    name = args[i]
    i += 1
    cmd = args[i:]

    if name not in state["containers"]:
        die(f"no such container: {name}")

    if workdir and not os.path.isdir(workdir):
        die(f"workdir does not exist: {workdir}")

    if interactive and cmd == ["sh"]:
        if workdir:
            os.chdir(workdir)
        os.execvp("sh", ["sh"])

    if not cmd:
        return 0
    proc = subprocess.run(cmd, cwd=workdir)
    return proc.returncode


def main():
    argv = sys.argv[1:]
    if not argv:
        die("missing command")
    state = load_state()
    cmd = argv[0]

    if cmd == "image":
        if len(argv) < 2:
            die("missing image subcommand")
        sub = argv[1]
        if sub == "ls":
            for name in sorted(state["images"]):
                print(name)
            return 0
        if sub == "rm":
            if len(argv) < 3:
                die("missing image name")
            name = argv[2]
            if name in state["images"]:
                state["images"].remove(name)
                save_state(state)
            return 0
        die(f"unsupported image subcommand: {sub}")

    if cmd == "volume":
        if len(argv) < 2:
            die("missing volume subcommand")
        sub = argv[1]
        if sub == "ls":
            for name in sorted(state["volumes"]):
                print(name)
            return 0
        if sub == "create":
            if len(argv) < 3:
                die("missing volume name")
            name = argv[2]
            if name not in state["volumes"]:
                state["volumes"].append(name)
                save_state(state)
            print(name)
            return 0
        if sub == "rm":
            if len(argv) < 3:
                die("missing volume name")
            name = argv[2]
            if name in state["volumes"]:
                state["volumes"].remove(name)
                save_state(state)
            return 0
        die(f"unsupported volume subcommand: {sub}")

    if cmd == "run":
        return handle_run(argv[1:], state)

    if cmd == "ls":
        for name, info in sorted(state["containers"].items()):
            if info.get("running"):
                print(f"{name} {info.get('image', '')}")
        return 0

    if cmd == "rm":
        if len(argv) < 2:
            die("missing rm args")
        name = argv[-1]
        if name in state["containers"]:
            del state["containers"][name]
            save_state(state)
        return 0

    if cmd == "exec":
        return handle_exec(argv[1:], state)

    if cmd == "build":
        if "-t" not in argv:
            die("build requires -t")
        tag = argv[argv.index("-t") + 1]
        if tag not in state["images"]:
            state["images"].append(tag)
            save_state(state)
        print(f"built {tag}")
        return 0

    if cmd == "stats":
        payload = {
            "memoryUsageBytes": 1048576,
            "memoryLimitBytes": 268435456,
            "cpuUsageUsec": 123456,
            "networkRxBytes": 1024,
            "networkTxBytes": 2048,
            "blockReadBytes": 4096,
            "blockWriteBytes": 8192,
            "numProcesses": 3,
        }
        print(json.dumps(payload))
        return 0

    die(f"unsupported command: {cmd}")


if __name__ == "__main__":
    sys.exit(main())
"""


@pytest.fixture
def mock_container_cli(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> dict[str, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_container = bin_dir / "container"
    fake_container.write_text(_FAKE_CONTAINER_SCRIPT)
    fake_container.chmod(0o755)

    state_file = tmp_path / "fake-container-state.json"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    old_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{bin_dir}:{old_path}")
    monkeypatch.setenv("FAKE_CONTAINER_STATE", str(state_file))
    monkeypatch.setenv("HOME", str(home_dir))

    return {
        "tmp_path": tmp_path,
        "state_file": state_file,
        "home_dir": home_dir,
        "workspace_dir": workspace_dir,
    }
