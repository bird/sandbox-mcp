#!/usr/bin/env python3
"""
Sandbox MCP Server
Exposes local Apple Containerization sandboxes as MCP tools.

Any MCP-compatible client (Claude Code, Claude Desktop, Cursor, etc.)
can call these tools to execute code in isolated Linux VMs.

Tools:
  - sandbox_exec:           Run a shell command (~60ms)
  - sandbox_python:         Execute Python code (~80ms)
  - sandbox_write_file:     Write a file to the sandbox
  - sandbox_read_file:      Read a file from the sandbox
  - sandbox_install:        Install packages via apk
  - sandbox_reset:          Destroy and recreate the sandbox (clean state)
  - sandbox_status:         Show pool and sandbox info
  - sandbox_upload:         Copy files from host into sandbox
  - sandbox_download:       Copy files from sandbox to host
  - sandbox_bg:             Run a command in the background
  - sandbox_logs:           Read output from a background process
  - sandbox_kill:           Kill a background process
  - sandbox_stats:          Show CPU/memory/disk usage
  - sandbox_snapshot:       Save sandbox state as a reusable image
  - sandbox_restore:        Boot from a saved snapshot
  - sandbox_list_snapshots: List available snapshots
  - sandbox_git_clone:      Clone a git repo into the sandbox
  - sandbox_sync_start:     Watch and live-sync a host directory
  - sandbox_sync_stop:      Stop a running sync job
  - sandbox_env:            Manage persistent environment variables
  - sandbox_clone:          Clone a running sandbox to a new name
  - sandbox_history:        Show recent command audit log
  - sandbox_batch_write:    Write multiple files in one transfer
  - sandbox_list:           List all active sandboxes
  - sandbox_destroy:        Permanently kill a sandbox (no reboot)
  - sandbox_delete_snapshot: Delete a saved snapshot image
  - sandbox_network_info:   Show IPs and connectivity between sandboxes
  - sandbox_build_image:    Build a container image from a Containerfile
  - sandbox_expose:         Forward a sandbox port to localhost (TCP proxy)
  - sandbox_unexpose:       Stop a port forward
  - sandbox_health:         Quick liveness/disk/memory check across all sandboxes
  - sandbox_images:         List all available container images

Install:
  cd sandbox-mcp && uv sync

Run:
  uv run sandbox-mcp

Claude Code:
  claude mcp add sandbox -- uv run --directory /path/to/sandbox-mcp sandbox-mcp
"""

import asyncio
import base64
import collections
import json
import logging
import os
import re
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from mcp.server.fastmcp import FastMCP

# ── Logging (stderr only — stdout is MCP protocol) ──────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("sandbox-mcp")

# ── Config ───────────────────────────────────────────────────────────────

DEFAULT_IMAGE = "mcp-dev"
DEFAULT_TIMEOUT = 30.0
MAX_OUTPUT = 50_000

SANDBOX_CPUS = 2
SANDBOX_MEMORY = "512M"

WORKSPACE_VOLUME = "mcp-workspace"

# How long to trust a health check before re-probing
HEALTH_CHECK_TTL = 10.0

SNAPSHOT_PREFIX = "mcp-snap-"

# Persistent cache volumes survive sandbox resets
CACHE_VOLUMES = {
    "mcp-cache-apk": "/var/cache/apk",
    "mcp-cache-pip": "/root/.cache/pip",
    "mcp-cache-npm": "/root/.npm",
}

# State file for session reconnect (XDG-friendly)
_STATE_DIR = os.path.expanduser("~/.local/state/sandbox-mcp")
STATE_FILE = os.path.join(_STATE_DIR, "state.json")

# Auto-cleanup: destroy sandboxes idle beyond this (seconds)
IDLE_TTL = 1800  # 30 minutes

# Incremental snapshot boot marker
BOOT_MARKER = "/tmp/.mcp-boot-marker"

# File sync
SYNC_POLL_INTERVAL = 1.0  # seconds between polls
SYNC_IGNORE = {".git", "node_modules", "__pycache__", ".venv", "venv", ".DS_Store"}

# Per-sandbox resource profiles: override CPUs/memory by sandbox name
SANDBOX_PROFILES: dict[str, dict] = {
    # "ml": {"cpus": 4, "memory": "2G"},
    # "build": {"cpus": 4, "memory": "1G"},
    # "nested": {"cpus": 2, "memory": "1G", "virtualization": True},
}

# Command audit log: max entries per sandbox
AUDIT_LOG_SIZE = 100

# Environment persistence file inside sandbox
ENV_FILE = "/etc/profile.d/mcp-env.sh"


# ── Helpers ──────────────────────────────────────────────────────────────

def _humanize_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


async def _run(
    cmd: list[str], timeout: float = 30.0, input_data: bytes = None
) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if input_data else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(
        proc.communicate(input=input_data), timeout=timeout
    )
    return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def _truncate(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    total = _humanize_bytes(len(text.encode()))
    return text[:limit] + f"\n[truncated — {total} total, showing first {_humanize_bytes(limit)}]"


def _sq(s: str) -> str:
    """Shell-safe single-quote a string. Handles embedded quotes."""
    return "'" + s.replace("'", "'\\''") + "'"


_ENV_KEY_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def _validate_env_key(key: str) -> bool:
    """Validate that an env var key is safe (alphanumeric + underscore)."""
    return bool(_ENV_KEY_RE.match(key))


def _format_export_line(key: str, value: str) -> str:
    """Create a shell-safe export line for ENV_FILE."""
    return f"export {key}={_sq(value)}"


def _output_tokens(stdout: str) -> set[str]:
    """Split CLI tabular/plain output into exact whitespace-delimited tokens."""
    tokens: set[str] = set()
    for line in stdout.splitlines():
        tokens.update(line.split())
    return tokens


def _output_has_token(stdout: str, token: str) -> bool:
    """Exact-token membership check for CLI output."""
    return token in _output_tokens(stdout)


# ── Persistent Shell ─────────────────────────────────────────────────────

class PersistentShell:
    """
    Maintains a single `container exec -i <name> sh` session.
    Commands are piped through it with delimiter-based framing.
    Eliminates per-call subprocess spawn + vsock handshake (~50ms saved).
    """

    def __init__(self):
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._lock = asyncio.Lock()
        self._sandbox_name: Optional[str] = None

    async def start(self, sandbox_name: str):
        """Open a persistent sh session inside the sandbox."""
        self._sandbox_name = sandbox_name
        self._proc = await asyncio.create_subprocess_exec(
            "container", "exec", "-i", sandbox_name, "sh",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        marker = f"__READY_{uuid.uuid4().hex[:8]}__"
        self._proc.stdin.write(f"echo {marker}\n".encode())
        await self._proc.stdin.drain()
        while True:
            line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=10)
            if marker in line.decode(errors="replace"):
                break
        log.info(f"Persistent shell open for {sandbox_name}")

    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def exec(
        self,
        command: str,
        timeout: float = DEFAULT_TIMEOUT,
        workdir: Optional[str] = None,
    ) -> dict:
        """Execute a command through the persistent shell."""
        if not self.is_alive():
            return {
                "stdout": "",
                "stderr": "Persistent shell is dead",
                "exit_code": -1,
                "duration_ms": 0,
            }
        async with self._lock:
            return await self._exec_locked(command, timeout, workdir)

    async def _exec_locked(self, command: str, timeout: float, workdir: Optional[str]) -> dict:
        marker = f"__MCP_{uuid.uuid4().hex[:8]}__"
        err_file = f"/tmp/_mcp_err_{marker}"

        parts = []
        if workdir:
            parts.append(f"cd {_sq(workdir)} 2>/dev/null;")
        parts.append(f"{{ {command} ; }} 2>{_sq(err_file)};")
        parts.append(f"__mcp_rc=$?;")
        parts.append(f"echo \"{marker}_RC_${{__mcp_rc}}\";")
        parts.append(f"cat {_sq(err_file)} 2>/dev/null;")
        parts.append(f"echo \"{marker}_ERR_DONE\";")
        parts.append(f"rm -f {_sq(err_file)} 2>/dev/null")

        full_cmd = " ".join(parts) + "\n"

        t0 = time.perf_counter()
        try:
            self._proc.stdin.write(full_cmd.encode())
            await self._proc.stdin.drain()

            stdout_lines = []
            exit_code = 0
            rc_marker = f"{marker}_RC_"
            while True:
                line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=timeout)
                if not line:
                    return {
                        "stdout": "".join(stdout_lines),
                        "stderr": "Shell process terminated unexpectedly",
                        "exit_code": -1,
                        "duration_ms": round((time.perf_counter() - t0) * 1000, 1),
                    }
                text = line.decode(errors="replace")
                if rc_marker in text:
                    prefix, _, rc_tail = text.partition(rc_marker)
                    if prefix:
                        stdout_lines.append(prefix)
                    try:
                        exit_code = int(rc_tail.strip())
                    except (ValueError, IndexError):
                        exit_code = -1
                    break
                stdout_lines.append(text)

            stderr_lines = []
            err_done_marker = f"{marker}_ERR_DONE"
            while True:
                line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=5)
                if not line:
                    break
                text = line.decode(errors="replace")
                if err_done_marker in text:
                    prefix, _, _ = text.partition(err_done_marker)
                    if prefix:
                        stderr_lines.append(prefix)
                    break
                stderr_lines.append(text)

            elapsed = (time.perf_counter() - t0) * 1000
            return {
                "stdout": _truncate("".join(stdout_lines).rstrip("\n")),
                "stderr": _truncate("".join(stderr_lines).rstrip("\n")),
                "exit_code": exit_code,
                "duration_ms": round(elapsed, 1),
            }

        except asyncio.TimeoutError:
            elapsed = (time.perf_counter() - t0) * 1000
            if self._proc and self._proc.returncode is None:
                self._proc.kill()
            return {
                "stdout": "",
                "stderr": f"Timed out after {timeout}s",
                "exit_code": -1,
                "duration_ms": round(elapsed, 1),
            }
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return {
                "stdout": "",
                "stderr": f"Shell error: {e}",
                "exit_code": -1,
                "duration_ms": round(elapsed, 1),
            }

    async def close(self):
        if self._proc and self._proc.returncode is None:
            self._proc.stdin.close()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                self._proc.kill()
        self._proc = None
        self._sandbox_name = None


# ── Background process tracker ───────────────────────────────────────────

@dataclass
class BgProcess:
    pid: str
    command: str
    log_file: str
    started_at: float = field(default_factory=time.time)


# ── Sync job tracker ─────────────────────────────────────────────────────

@dataclass
class SyncJob:
    local_dir: str
    sandbox_dir: str
    sandbox_name: str
    task: Optional[asyncio.Task] = field(default=None, repr=False)
    last_sync: float = field(default=0.0)
    files_synced: int = 0


# ── Port forward tracker ─────────────────────────────────────────────────

@dataclass
class PortForward:
    host_port: int
    container_port: int
    sandbox_name: str
    _server: Optional[asyncio.AbstractServer] = field(default=None, repr=False)
    _connections: int = field(default=0, repr=False)
    started_at: float = field(default_factory=time.time)


# ── Audit log entry ──────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    command: str
    exit_code: int
    duration_ms: float
    timestamp: float = field(default_factory=time.time)


# ── Sandbox ──────────────────────────────────────────────────────────────

@dataclass
class Sandbox:
    name: str
    image: str
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    _shell: PersistentShell = field(default_factory=PersistentShell, repr=False)
    _last_healthy: float = field(default=0.0, repr=False)
    _known_dirs: set = field(default_factory=set, repr=False)
    _bg_processes: dict = field(default_factory=dict, repr=False)
    _ip_address: Optional[str] = field(default=None, repr=False)
    _audit_log: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=AUDIT_LOG_SIZE), repr=False
    )

    def touch(self):
        """Update last activity timestamp (for TTL tracking)."""
        self.last_activity = time.time()

    def _audit(self, command: str, result: dict):
        """Record command metadata in the audit log."""
        self._audit_log.append(AuditEntry(
            command=command[:200],
            exit_code=result.get("exit_code", -1),
            duration_ms=result.get("duration_ms", 0),
        ))

    async def open_shell(self):
        """Open the persistent shell session."""
        await self._shell.start(self.name)
        self._last_healthy = time.time()
        self.touch()

    async def exec(
        self,
        command: str,
        timeout: float = DEFAULT_TIMEOUT,
        workdir: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        audit: bool = True,
    ) -> dict:
        """Execute via persistent shell (fast path) or subprocess (fallback)."""
        self.touch()
        if env:
            env_prefix = " ".join(f"{k}={_sq(v)}" for k, v in env.items()) + " "
            command = env_prefix + command

        # Source persistent env vars when present, without failing if missing.
        full_command = (
            f"if [ -f {_sq(ENV_FILE)} ]; then . {_sq(ENV_FILE)} 2>/dev/null; fi; "
            f"{command}"
        )

        if self._shell.is_alive():
            result = await self._shell.exec(full_command, timeout=timeout, workdir=workdir)
            if result["exit_code"] != -1 or "Timed out" in result.get("stderr", ""):
                self._last_healthy = time.time()
                if audit:
                    self._audit(command, result)
                return result
            log.warning("Persistent shell died, falling back to subprocess")

        result = await self._exec_subprocess(full_command, timeout=timeout, workdir=workdir)
        if audit:
            self._audit(command, result)
        return result

    async def _exec_subprocess(
        self,
        command: str,
        timeout: float = DEFAULT_TIMEOUT,
        workdir: Optional[str] = None,
    ) -> dict:
        """Fallback: spawn a new container exec process."""
        cmd = ["container", "exec"]
        if workdir:
            cmd.extend(["-w", workdir])
        cmd.extend([self.name, "sh", "-c", command])

        t0 = time.perf_counter()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            elapsed = (time.perf_counter() - t0) * 1000
            return {
                "stdout": _truncate(stdout.decode(errors="replace")),
                "stderr": _truncate(stderr.decode(errors="replace")),
                "exit_code": proc.returncode or 0,
                "duration_ms": round(elapsed, 1),
            }
        except asyncio.TimeoutError:
            proc.kill()
            elapsed = (time.perf_counter() - t0) * 1000
            return {
                "stdout": "",
                "stderr": f"Timed out after {timeout}s",
                "exit_code": -1,
                "duration_ms": round(elapsed, 1),
            }

    async def exec_raw(
        self,
        command: str,
        timeout: float = DEFAULT_TIMEOUT,
        workdir: Optional[str] = None,
    ) -> tuple[int, bytes, bytes]:
        """Execute and return raw bytes (for binary file transfer). Always uses subprocess."""
        self.touch()
        cmd = ["container", "exec"]
        if workdir:
            cmd.extend(["-w", workdir])
        cmd.extend([self.name, "sh", "-c", command])
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, stdout, stderr

    async def write_bytes(
        self,
        path: str,
        data: bytes,
        timeout: float = 60.0,
    ) -> tuple[int, str]:
        """Write raw bytes via stdin to avoid shell/argv size limits."""
        self.touch()
        cmd = [
            "container", "exec", "-i", self.name,
            "sh", "-c", f"mkdir -p $(dirname {_sq(path)}) && cat > {_sq(path)}",
        ]
        code, _, stderr = await _run(cmd, timeout=timeout, input_data=data)
        return code, stderr

    async def ensure_dir(self, path: str):
        """Create directory only if we haven't already this session."""
        if path not in self._known_dirs:
            await self.exec(f"mkdir -p {_sq(path)}", audit=False)
            self._known_dirs.add(path)

    def health_ok(self) -> bool:
        """Check if we can skip the health probe (cached)."""
        return (time.time() - self._last_healthy) < HEALTH_CHECK_TTL

    async def health_check(self) -> bool:
        """Full health check — only called when cache expired."""
        if self.health_ok():
            return True
        try:
            result = await self._exec_subprocess("echo ok", timeout=5)
            alive = result["exit_code"] == 0 and "ok" in result["stdout"]
            if alive:
                self._last_healthy = time.time()
            return alive
        except Exception:
            return False

    async def get_ip(self) -> Optional[str]:
        """Get the sandbox VM's IP address (cached)."""
        if self._ip_address:
            return self._ip_address
        result = await self.exec("hostname -i 2>/dev/null | awk '{print $1}'", audit=False)
        ip = result["stdout"].strip()
        if ip and ip != "127.0.0.1":
            self._ip_address = ip
        return self._ip_address

    async def destroy(self):
        await self._shell.close()
        await _run(["container", "rm", "--force", self.name], timeout=10)


# ── Volume management ────────────────────────────────────────────────────
# Apple Containerization does NOT allow the same volume mounted by
# multiple containers simultaneously.  Each named sandbox therefore
# gets its own set of volumes:  mcp-workspace-{name}, mcp-cache-*-{name}.
# ─────────────────────────────────────────────────────────────────────────

def _vol_name(base: str, sandbox_name: str) -> str:
    """Volume name scoped to a sandbox: mcp-workspace-default, mcp-cache-apk-api, etc."""
    return f"{base}-{sandbox_name}"


async def _ensure_sandbox_volumes(sandbox_name: str) -> dict:
    """Ensure volumes exist for a specific named sandbox. Returns mount map."""
    code, stdout, _ = await _run(["container", "volume", "ls"], timeout=10)
    existing = _output_tokens(stdout)
    mounts = {}

    # Workspace volume
    ws = _vol_name(WORKSPACE_VOLUME, sandbox_name)
    if ws not in existing:
        c, _, err = await _run(["container", "volume", "create", ws], timeout=10)
        if c == 0:
            log.info(f"Created volume: {ws}")
        else:
            log.warning(f"Could not create {ws}: {err.strip()}")
            ws = None
    mounts["workspace"] = ws

    # Cache volumes
    for cache_base, mount_path in CACHE_VOLUMES.items():
        vol = _vol_name(cache_base, sandbox_name)
        if vol not in existing:
            c, _, _ = await _run(["container", "volume", "create", vol], timeout=10)
            if c == 0:
                log.info(f"Created cache volume: {vol}")
            else:
                continue
        mounts[vol] = mount_path

    return mounts


# ── Orphan cleanup ───────────────────────────────────────────────────────

async def _cleanup_orphans():
    """Remove stale mcp-sb-* containers and orphaned volumes from crashed sessions."""
    saved = {}
    try:
        with open(STATE_FILE) as f:
            saved = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Safety: without valid persisted ownership data, never delete resources.
    if not saved:
        return

    # Collect container names we expect to be alive
    expected_containers = {info["container"] for info in saved.values()}

    # Find all running mcp-sb-* containers
    code, stdout, _ = await _run(["container", "ls"], timeout=10)
    if code != 0:
        return

    orphan_containers = []
    for line in stdout.strip().split("\n"):
        for token in line.split():
            if token.startswith("mcp-sb-") and token not in expected_containers:
                orphan_containers.append(token)
                break

    # Kill orphan containers
    for name in orphan_containers:
        log.info(f"Orphan cleanup: removing stale container {name}")
        await _run(["container", "rm", "--force", name], timeout=10)

    # Find orphaned volumes (mcp-* volumes not associated with any known sandbox)
    code, vol_stdout, _ = await _run(["container", "volume", "ls"], timeout=10)
    if code != 0:
        return

    # Build set of volume names we expect to exist
    known_sandbox_names = set(saved.keys())
    expected_volumes = set()
    for sb_name in known_sandbox_names:
        expected_volumes.add(_vol_name(WORKSPACE_VOLUME, sb_name))
        for cache_base in CACHE_VOLUMES:
            expected_volumes.add(_vol_name(cache_base, sb_name))

    for line in vol_stdout.strip().split("\n"):
        vol = line.strip()
        if not vol:
            continue
        # Only clean up mcp-workspace-* and mcp-cache-* volumes
        is_mcp_vol = vol.startswith("mcp-workspace-") or vol.startswith("mcp-cache-")
        if is_mcp_vol and vol not in expected_volumes:
            log.info(f"Orphan cleanup: removing stale volume {vol}")
            await _run(["container", "volume", "rm", vol], timeout=10)

    if orphan_containers:
        log.info(f"Orphan cleanup: removed {len(orphan_containers)} container(s)")


# ── Boot ─────────────────────────────────────────────────────────────────

async def _boot(
    name: str,
    image: str,
    mounts: dict = None,
    cpus: int = SANDBOX_CPUS,
    memory: str = SANDBOX_MEMORY,
    virtualization: bool = False,
) -> Sandbox:
    cmd = [
        "container", "run", "-d",
        "--name", name,
        "--cpus", str(cpus),
        "--memory", memory,
    ]
    if virtualization:
        cmd.append("--virtualization")
    if mounts:
        ws = mounts.get("workspace")
        if ws:
            cmd.extend(["--volume", f"{ws}:/workspace"])
        for key, mount_path in mounts.items():
            if key != "workspace" and mount_path.startswith("/"):
                cmd.extend(["--volume", f"{key}:{mount_path}"])
    cmd.extend([image, "sh", "-c", "sleep infinity"])

    code, _, stderr = await _run(cmd, timeout=30)
    if code != 0:
        raise RuntimeError(f"Boot failed: {stderr.strip()}")

    sb = Sandbox(name=name, image=image)
    await sb.open_shell()

    # Enable apk cache (symlink so apk uses the mounted volume)
    await sb.exec("ln -sf /var/cache/apk /etc/apk/cache 2>/dev/null; true", audit=False)

    # Set boot marker for incremental snapshots
    await sb.exec(f"touch {BOOT_MARKER}", audit=False)

    # Initialize empty env file
    await sb.exec(f"touch {ENV_FILE}", audit=False)

    return sb


# ── Sandbox manager (multi-sandbox) ──────────────────────────────────────

class SandboxManager:
    """Manages named sandboxes, each with its own volumes."""

    def __init__(self, image: str = DEFAULT_IMAGE):
        self.image = image
        self._sandboxes: dict[str, Sandbox] = {}
        self._sandbox_mounts: dict[str, dict] = {}
        self._sync_jobs: dict[str, SyncJob] = {}
        self._port_forwards: dict[int, PortForward] = {}  # host_port -> PortForward
        self._started = False
        self._cleanup_task: Optional[asyncio.Task] = None
        self._network_available = False
        self._boot_locks: dict[str, asyncio.Lock] = {}  # per-sandbox boot lock

    async def ensure_started(self):
        if self._started:
            return
        self._started = True

        # Check image exists
        if not await self.check_image():
            log.warning(f"Image '{self.image}' not found — first sandbox boot will fail until image is built")

        # Clean up orphan containers/volumes from crashed sessions
        await _cleanup_orphans()

        # Inter-sandbox networking: Apple Containers puts all VMs on the
        # default network (192.168.65.0/24).  Custom networks break DNS and
        # don't route between VMs, so we use the default and wire /etc/hosts.
        self._network_available = True

        # Session reconnect: rediscover running mcp-sb-* containers
        await self._reconnect_existing()

        # Warm start: pre-boot default sandbox eagerly
        if "default" not in self._sandboxes:
            asyncio.create_task(self._warm_boot())

        # Start auto-cleanup loop
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        log.info(
            f"Sandbox manager ready (image={self.image}, "
            f"reconnected={len(self._sandboxes)}, "
            f"network={'yes' if self._network_available else 'no'})"
        )

    # ── Session reconnect ────────────────────────────────────────────

    def _save_state(self):
        """Persist sandbox name -> container name mapping to disk."""
        state = {}
        for sb_name, sb in self._sandboxes.items():
            state[sb_name] = {
                "container": sb.name,
                "image": sb.image,
                "created_at": sb.created_at,
            }
        try:
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(STATE_FILE, "w") as f:
                json.dump(state, f)
        except Exception as e:
            log.warning(f"Could not save state: {e}")

    def _load_state(self) -> dict:
        """Load saved state from disk."""
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    async def _reconnect_existing(self):
        """On startup, find running mcp-sb-* containers and reconnect."""
        saved = self._load_state()
        if not saved:
            return

        # Get list of actually running containers
        code, stdout, _ = await _run(["container", "ls"], timeout=10)
        if code != 0:
            return

        running_containers = _output_tokens(stdout)

        reconnected = 0
        for sb_name, info in saved.items():
            container_name = info["container"]
            if container_name not in running_containers:
                continue

            try:
                sb = Sandbox(
                    name=container_name,
                    image=info.get("image", self.image),
                    created_at=info.get("created_at", time.time()),
                )
                # Try to open a persistent shell
                await sb.open_shell()
                if await sb.health_check():
                    self._sandboxes[sb_name] = sb
                    # Rebuild mount map
                    mounts = await _ensure_sandbox_volumes(sb_name)
                    self._sandbox_mounts[sb_name] = mounts
                    reconnected += 1
                    log.info(f"Reconnected sandbox '{sb_name}': {container_name}")
                else:
                    await sb._shell.close()
            except Exception as e:
                log.warning(f"Could not reconnect '{sb_name}' ({container_name}): {e}")

        if reconnected > 0:
            log.info(f"Reconnected {reconnected} sandbox(es) from previous session")

    # ── Warm start ───────────────────────────────────────────────────

    async def _warm_boot(self):
        """Pre-boot default sandbox so first command doesn't wait 2-3s."""
        try:
            log.info("Warm-starting default sandbox...")
            await self.get_sandbox("default")
            log.info("Default sandbox warm and ready")
        except Exception as e:
            log.warning(f"Warm boot failed (will cold-boot on first use): {e}")

    # ── Auto-cleanup ─────────────────────────────────────────────────

    async def _cleanup_loop(self):
        """Periodically destroy sandboxes idle beyond IDLE_TTL."""
        while True:
            try:
                await asyncio.sleep(60)  # check every minute
                now = time.time()
                to_destroy = []
                for sb_name, sb in self._sandboxes.items():
                    if sb_name == "default":
                        continue  # never auto-destroy default
                    idle_secs = now - sb.last_activity
                    if idle_secs > IDLE_TTL:
                        to_destroy.append(sb_name)

                for sb_name in to_destroy:
                    sb = self._sandboxes[sb_name]
                    log.info(
                        f"Auto-cleanup: destroying idle sandbox '{sb_name}' "
                        f"({sb.name}, idle {(now - sb.last_activity)/60:.0f}min)"
                    )
                    # Stop port forwards and sync jobs targeting this sandbox
                    await self._cleanup_forwards_for(sb_name)
                    for job_id, job in list(self._sync_jobs.items()):
                        if job.sandbox_name == sb_name:
                            await self._stop_sync(job_id)
                    try:
                        await sb.destroy()
                    except Exception:
                        pass
                    del self._sandboxes[sb_name]
                    self._save_state()

            except asyncio.CancelledError:
                return
            except Exception as e:
                log.warning(f"Cleanup loop error: {e}")

    # ── Inter-sandbox networking ─────────────────────────────────────

    async def _update_hosts(self):
        """Update /etc/hosts in all sandboxes so they can reach each other by name."""
        if not self._network_available:
            return

        # Collect all sandbox IPs
        entries = []
        for sb_name, sb in self._sandboxes.items():
            try:
                ip = await sb.get_ip()
                if ip:
                    entries.append((ip, sb_name))
            except Exception:
                continue

        if len(entries) < 2:
            return  # nothing to connect

        # Push to all sandboxes
        for sb_name, sb in self._sandboxes.items():
            try:
                # Remove old mcp entries, then add fresh ones
                peer_cmds = " && ".join(
                    f"echo {_sq(f'{ip} {name} # mcp-peer')} >> /etc/hosts"
                    for ip, name in entries
                    if name != sb_name  # don't add self
                )
                if peer_cmds:
                    await sb.exec(
                        f"sed -i '/ # mcp-peer$/d' /etc/hosts; {peer_cmds}",
                        audit=False,
                    )
            except Exception as e:
                log.warning(f"Could not update hosts in '{sb_name}': {e}")

    # ── File sync ────────────────────────────────────────────────────

    async def start_sync(
        self, local_dir: str, sandbox_dir: str, sandbox_name: str = "default"
    ) -> str:
        """Start watching a local directory and syncing changes to sandbox."""
        local_dir = os.path.expanduser(local_dir)
        if not os.path.isdir(local_dir):
            return f"Error: {local_dir} is not a directory"

        job_id = f"sync-{uuid.uuid4().hex[:6]}"
        job = SyncJob(
            local_dir=local_dir,
            sandbox_dir=sandbox_dir,
            sandbox_name=sandbox_name,
        )

        # Do an initial full sync
        sb = await self.get_sandbox(sandbox_name)
        await sb.ensure_dir(sandbox_dir)
        count = await self._do_full_sync(sb, local_dir, sandbox_dir)

        # Start polling task
        job.task = asyncio.create_task(self._sync_poll(job_id, job))
        job.last_sync = time.time()
        job.files_synced = count
        self._sync_jobs[job_id] = job

        return (
            f"Sync started [{job_id}]: {local_dir} -> {sandbox_name}:{sandbox_dir}\n"
            f"Initial sync: {count} files\n"
            f"Polling every {SYNC_POLL_INTERVAL}s (ignoring {', '.join(sorted(SYNC_IGNORE))})"
        )

    async def _do_full_sync(self, sb: Sandbox, local_dir: str, sandbox_dir: str) -> int:
        """Tar the local dir and extract in sandbox. Returns file count."""
        excludes = []
        for ign in SYNC_IGNORE:
            excludes.extend(["--exclude", ign])

        tar_proc = await asyncio.create_subprocess_exec(
            "tar", "-cf", "-", *excludes, "-C", local_dir, ".",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        tar_data, tar_err = await tar_proc.communicate()
        if tar_proc.returncode != 0:
            log.warning(f"Sync tar error: {tar_err.decode(errors='replace')}")
            return 0

        cmd = ["container", "exec", "-i", sb.name, "sh", "-c", f"tar -xf - -C {_sq(sandbox_dir)}"]
        code, _, stderr = await _run(cmd, timeout=60, input_data=tar_data)
        if code != 0:
            log.warning(f"Sync extract error: {stderr}")
            return 0

        count_result = await sb.exec(f"find {_sq(sandbox_dir)} -type f | wc -l", audit=False)
        try:
            return int(count_result["stdout"].strip())
        except ValueError:
            return 0

    async def _sync_poll(self, job_id: str, job: SyncJob):
        """Poll for file changes and push incremental updates."""
        last_mtimes: dict[str, float] = {}
        self._scan_mtimes(job.local_dir, last_mtimes)

        while True:
            try:
                await asyncio.sleep(SYNC_POLL_INTERVAL)

                if job_id not in self._sync_jobs:
                    return

                current_mtimes: dict[str, float] = {}
                self._scan_mtimes(job.local_dir, current_mtimes)

                changed = []
                for rel_path, mtime in current_mtimes.items():
                    if rel_path not in last_mtimes or last_mtimes[rel_path] < mtime:
                        changed.append(rel_path)

                deleted = set(last_mtimes.keys()) - set(current_mtimes.keys())

                if not changed and not deleted:
                    continue

                sb = await self.get_sandbox(job.sandbox_name)

                for rel_path in changed:
                    abs_path = os.path.join(job.local_dir, rel_path)
                    dest = f"{job.sandbox_dir}/{rel_path}"
                    try:
                        with open(abs_path, "rb") as f:
                            data = f.read()
                        code, stderr = await sb.write_bytes(dest, data, timeout=60)
                        if code != 0:
                            raise RuntimeError(stderr.strip() or "write failed")
                        job.files_synced += 1
                    except Exception as e:
                        log.warning(f"Sync upload failed for {rel_path}: {e}")

                for rel_path in deleted:
                    dest = f"{job.sandbox_dir}/{rel_path}"
                    await sb.exec(f"rm -f {_sq(dest)} 2>/dev/null", audit=False)

                if changed or deleted:
                    log.info(
                        f"Sync [{job_id}]: {len(changed)} changed, "
                        f"{len(deleted)} deleted"
                    )

                last_mtimes = current_mtimes
                job.last_sync = time.time()

            except asyncio.CancelledError:
                return
            except Exception as e:
                log.warning(f"Sync poll error [{job_id}]: {e}")

    def _scan_mtimes(self, root: str, out: dict):
        """Walk a directory tree and record relative path -> mtime."""
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SYNC_IGNORE]
            for fname in filenames:
                if fname in SYNC_IGNORE:
                    continue
                abs_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(abs_path, root)
                try:
                    out[rel_path] = os.path.getmtime(abs_path)
                except OSError:
                    pass

    async def _stop_sync(self, job_id: str) -> str:
        if job_id not in self._sync_jobs:
            available = ", ".join(self._sync_jobs.keys()) if self._sync_jobs else "none"
            return f"Error: no sync job '{job_id}'. Active: {available}"

        job = self._sync_jobs[job_id]
        if job.task and not job.task.done():
            job.task.cancel()
            try:
                await job.task
            except asyncio.CancelledError:
                pass

        del self._sync_jobs[job_id]
        return (
            f"Stopped sync [{job_id}]: {job.local_dir} -> "
            f"{job.sandbox_name}:{job.sandbox_dir} "
            f"({job.files_synced} files synced total)"
        )

    # ── Core sandbox lifecycle ───────────────────────────────────────

    def _get_profile(self, sandbox_name: str) -> tuple[int, str, bool]:
        """Get CPU/memory/virtualization for a sandbox name from profiles or defaults."""
        profile = SANDBOX_PROFILES.get(sandbox_name, {})
        cpus = profile.get("cpus", SANDBOX_CPUS)
        memory = profile.get("memory", SANDBOX_MEMORY)
        virtualization = profile.get("virtualization", False)
        return cpus, memory, virtualization

    async def _boot_for(self, sandbox_name: str) -> Sandbox:
        """Cold-boot a sandbox with per-name volumes."""
        mounts = await _ensure_sandbox_volumes(sandbox_name)
        self._sandbox_mounts[sandbox_name] = mounts
        container_name = f"mcp-sb-{uuid.uuid4().hex[:6]}"
        cpus, memory, virtualization = self._get_profile(sandbox_name)
        sb = await _boot(
            container_name,
            self.image,
            mounts,
            cpus=cpus,
            memory=memory,
            virtualization=virtualization,
        )
        virt_str = " +virt" if virtualization else ""
        log.info(f"Booted sandbox '{sandbox_name}': {sb.name} ({cpus} CPUs, {memory}{virt_str})")
        return sb

    async def get_sandbox(self, name: str = "default") -> Sandbox:
        await self.ensure_started()

        # Fast path: already booted and healthy (no lock needed)
        if name in self._sandboxes:
            sb = self._sandboxes[name]
            sb.touch()
            if sb.health_ok():
                return sb

        # Slow path: need to boot or health-check — use per-name lock
        # to prevent race between warm boot and first tool call
        if name not in self._boot_locks:
            self._boot_locks[name] = asyncio.Lock()

        async with self._boot_locks[name]:
            # Re-check after acquiring lock (another task may have booted it)
            if name in self._sandboxes:
                sb = self._sandboxes[name]
                sb.touch()
                if sb.health_ok():
                    return sb
                if await sb.health_check():
                    return sb
                log.warning(f"Sandbox '{name}' ({sb.name}) is dead, rotating...")
                try:
                    await sb.destroy()
                except Exception:
                    pass
                del self._sandboxes[name]

            sb = await self._boot_for(name)
            self._sandboxes[name] = sb
            self._save_state()

            # Update /etc/hosts across all sandboxes for networking
            if self._network_available and len(self._sandboxes) > 1:
                asyncio.create_task(self._update_hosts())

            return sb

    async def _exec_with_recovery(self, sb: Sandbox, command: str, **kwargs) -> dict:
        result = await sb.exec(command, **kwargs)
        if result["exit_code"] == -1 and "Timed out" not in result["stderr"]:
            if not await sb.health_check():
                log.warning(f"Sandbox {sb.name} crashed during exec, recovering...")
                sb_name = next((n for n, s in self._sandboxes.items() if s is sb), None)
                try:
                    await sb.destroy()
                except Exception:
                    pass
                if sb_name:
                    del self._sandboxes[sb_name]
                    new_sb = await self.get_sandbox(sb_name)
                    return await new_sb.exec(command, **kwargs)
        return result

    async def reset(self, name: str = "default", wipe_workspace: bool = False) -> str:
        await self._cleanup_forwards_for(name)
        if name in self._sandboxes:
            sb = self._sandboxes[name]
            old_name = sb.name
            await sb.destroy()
            del self._sandboxes[name]
            log.info(f"Destroyed '{name}' ({old_name})")

        if wipe_workspace:
            ws = _vol_name(WORKSPACE_VOLUME, name)
            await _run(["container", "volume", "rm", ws], timeout=10)
            log.info(f"Workspace volume {ws} wiped")

        sb = await self.get_sandbox(name)
        ws_note = " (workspace preserved)" if not wipe_workspace else " (workspace wiped)"
        return f"Fresh sandbox '{name}' ready: {sb.name}{ws_note}"

    # ── Environment persistence ──────────────────────────────────────

    async def set_env(self, sandbox_name: str, key: str, value: str) -> str:
        """Set a persistent env var in the sandbox."""
        if not _validate_env_key(key):
            return f"Error: invalid env key '{key}' (must be [A-Za-z_][A-Za-z0-9_]*)"
        sb = await self.get_sandbox(sandbox_name)
        export_line = _format_export_line(key, value) + "\n"
        export_b64 = base64.b64encode(export_line.encode()).decode()
        tmp_path = f"/tmp/.mcp-env-{uuid.uuid4().hex[:8]}"
        # Remove existing line for this key, then append
        await sb.exec(
            f"touch {_sq(ENV_FILE)}; "
            f"grep -v -E '^export {key}=' {_sq(ENV_FILE)} > {_sq(tmp_path)} || true; "
            f"mv {_sq(tmp_path)} {_sq(ENV_FILE)}; "
            f"echo '{export_b64}' | base64 -d >> {_sq(ENV_FILE)}",
            audit=False,
        )
        return f"Set {key} in '{sandbox_name}' (persists across commands)"

    async def get_env(self, sandbox_name: str) -> str:
        """Get all persistent env vars."""
        sb = await self.get_sandbox(sandbox_name)
        result = await sb.exec(f"cat {ENV_FILE} 2>/dev/null", audit=False)
        return result["stdout"].strip() if result["exit_code"] == 0 else ""

    async def unset_env(self, sandbox_name: str, key: str) -> str:
        """Remove a persistent env var."""
        if not _validate_env_key(key):
            return f"Error: invalid env key '{key}' (must be [A-Za-z_][A-Za-z0-9_]*)"
        sb = await self.get_sandbox(sandbox_name)
        tmp_path = f"/tmp/.mcp-env-{uuid.uuid4().hex[:8]}"
        await sb.exec(
            f"touch {_sq(ENV_FILE)}; "
            f"grep -v -E '^export {key}=' {_sq(ENV_FILE)} > {_sq(tmp_path)} || true; "
            f"mv {_sq(tmp_path)} {_sq(ENV_FILE)}",
            audit=False,
        )
        return f"Unset {key} in '{sandbox_name}'"

    # ── Sandbox clone ────────────────────────────────────────────────

    async def clone(self, source_name: str, target_name: str) -> str:
        """Clone a running sandbox to a new name via tar pipe."""
        if source_name not in self._sandboxes:
            return f"Error: no active sandbox '{source_name}' to clone"
        if target_name in self._sandboxes:
            return f"Error: sandbox '{target_name}' already exists. Reset it first."

        src = self._sandboxes[source_name]
        t0 = time.perf_counter()

        # Export source filesystem
        code, raw_tar, raw_err = await src.exec_raw(
            "tar -cf - --exclude='/workspace' --exclude='/proc' "
            "--exclude='/sys' --exclude='/dev' /",
            timeout=120,
        )
        if code != 0 and not raw_tar:
            return f"Error exporting: {raw_err.decode(errors='replace')}"

        # Boot target
        mounts = await _ensure_sandbox_volumes(target_name)
        self._sandbox_mounts[target_name] = mounts
        container_name = f"mcp-sb-{uuid.uuid4().hex[:6]}"
        cpus, memory, virt = self._get_profile(target_name)
        tgt = await _boot(container_name, self.image, mounts, cpus=cpus, memory=memory, virtualization=virt)

        # Inject filesystem
        cmd = ["container", "exec", "-i", tgt.name, "sh", "-c", "tar -xpf - -C / 2>/dev/null"]
        inject_code, _, inject_err = await _run(cmd, timeout=120, input_data=raw_tar)

        self._sandboxes[target_name] = tgt
        self._save_state()

        # Update hosts
        if self._network_available and len(self._sandboxes) > 1:
            asyncio.create_task(self._update_hosts())

        elapsed = (time.perf_counter() - t0) * 1000
        size = _humanize_bytes(len(raw_tar))
        return (
            f"Cloned '{source_name}' -> '{target_name}': {tgt.name} "
            f"({size}, {elapsed:.0f}ms)"
        )

    # ── Command audit log ────────────────────────────────────────────

    def get_history(self, sandbox_name: str, limit: int = 20) -> list[dict]:
        """Get recent command history for a sandbox."""
        if sandbox_name not in self._sandboxes:
            return []
        entries = list(self._sandboxes[sandbox_name]._audit_log)
        entries.reverse()  # most recent first
        return [
            {
                "command": e.command,
                "exit_code": e.exit_code,
                "duration_ms": e.duration_ms,
                "ago": f"{time.time() - e.timestamp:.0f}s",
            }
            for e in entries[:limit]
        ]

    # ── Batch file write ─────────────────────────────────────────────

    async def write_files(self, sandbox_name: str, files: dict[str, str]) -> str:
        """Write multiple files in one tar transfer."""
        sb = await self.get_sandbox(sandbox_name)
        t0 = time.perf_counter()

        with tempfile.TemporaryDirectory() as tmpdir:
            for path, content in files.items():
                # path should be absolute like /workspace/foo.py
                # Strip leading / for tar
                rel = path.lstrip("/")
                full = os.path.join(tmpdir, rel)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "w") as f:
                    f.write(content)

            tar_proc = await asyncio.create_subprocess_exec(
                "tar", "-cf", "-", "-C", tmpdir, ".",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            tar_data, _ = await tar_proc.communicate()

            cmd = ["container", "exec", "-i", sb.name, "sh", "-c", "tar -xf - -C /"]
            code, _, stderr = await _run(cmd, timeout=60, input_data=tar_data)
            if code != 0:
                return f"Error: {stderr}"

        elapsed = (time.perf_counter() - t0) * 1000
        return f"Wrote {len(files)} files ({elapsed:.0f}ms): {', '.join(files.keys())}"

    # ── Snapshot ─────────────────────────────────────────────────────

    async def snapshot(
        self,
        snapshot_name: str,
        sandbox_name: str = "default",
        incremental: bool = True,
    ) -> str:
        """Save a sandbox's current state as a reusable image via tar + build."""
        if sandbox_name not in self._sandboxes:
            return f"Error: no active sandbox '{sandbox_name}' to snapshot"

        sb = self._sandboxes[sandbox_name]
        image_name = f"{SNAPSHOT_PREFIX}{snapshot_name}"
        t0 = time.perf_counter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = os.path.join(tmpdir, "rootfs.tar")

            # Check if boot marker exists for incremental
            if incremental:
                marker_check = await sb.exec(
                    f"test -f {BOOT_MARKER} && echo yes || echo no", audit=False
                )
                has_marker = "yes" in marker_check["stdout"]
            else:
                has_marker = False

            if incremental and has_marker:
                log.info(f"Incremental snapshot for '{sandbox_name}'")
                code, raw_tar, raw_err = await sb.exec_raw(
                    f"find / -newer {BOOT_MARKER} "
                    f"-not -path '/workspace/*' "
                    f"-not -path '/proc/*' "
                    f"-not -path '/sys/*' "
                    f"-not -path '/dev/*' "
                    f"-not -path '/tmp/*' "
                    f"-not -name '.mcp-boot-marker' "
                    f"2>/dev/null | tar -cf - -T - 2>/dev/null",
                    timeout=120,
                )
            else:
                log.info(f"Full snapshot for '{sandbox_name}'")
                code, raw_tar, raw_err = await sb.exec_raw(
                    "tar -cf - --exclude='/workspace' --exclude='/proc' "
                    "--exclude='/sys' --exclude='/dev' /",
                    timeout=120,
                )

            if code != 0 and not raw_tar:
                return f"Error exporting filesystem: {raw_err.decode(errors='replace')}"

            with open(tar_path, "wb") as f:
                f.write(raw_tar)

            cf_path = os.path.join(tmpdir, "Containerfile")
            with open(cf_path, "w") as f:
                f.write(f"FROM {self.image}\n")
                f.write("COPY rootfs.tar /tmp/rootfs.tar\n")
                f.write("RUN tar -xpf /tmp/rootfs.tar -C / 2>/dev/null; rm -f /tmp/rootfs.tar\n")
                f.write("WORKDIR /workspace\n")

            code, stdout, stderr = await _run(
                ["container", "build", "-t", image_name, tmpdir],
                timeout=120,
            )
            if code != 0:
                return f"Error building snapshot: {stderr.strip()}"

        await sb.exec(f"touch {BOOT_MARKER}", audit=False)

        elapsed = (time.perf_counter() - t0) * 1000
        size = _humanize_bytes(len(raw_tar))
        mode = "incremental" if (incremental and has_marker) else "full"
        return f"Snapshot '{snapshot_name}' saved from {sb.name} ({mode}, {size}, {elapsed:.0f}ms)"

    async def restore(self, snapshot_name: str, sandbox_name: str = "default") -> str:
        """Destroy a sandbox and boot from a saved snapshot."""
        image_name = f"{SNAPSHOT_PREFIX}{snapshot_name}"

        code, stdout, _ = await _run(["container", "image", "ls"], timeout=10)
        if not _output_has_token(stdout, image_name):
            return f"Error: snapshot '{snapshot_name}' not found. Use sandbox_list_snapshots()."

        if sandbox_name in self._sandboxes:
            await self._cleanup_forwards_for(sandbox_name)
            await self._sandboxes[sandbox_name].destroy()
            del self._sandboxes[sandbox_name]

        new_name = f"mcp-sb-{uuid.uuid4().hex[:6]}"
        try:
            mounts = await _ensure_sandbox_volumes(sandbox_name)
            self._sandbox_mounts[sandbox_name] = mounts
            cpus, memory, virt = self._get_profile(sandbox_name)
            sb = await _boot(new_name, image_name, mounts, cpus=cpus, memory=memory, virtualization=virt)
            self._sandboxes[sandbox_name] = sb
            self._save_state()

            if self._network_available and len(self._sandboxes) > 1:
                asyncio.create_task(self._update_hosts())

            return f"Restored '{snapshot_name}' as '{sandbox_name}': {sb.name}"
        except Exception as e:
            return f"Error restoring: {e}"

    async def list_snapshots(self) -> list[str]:
        code, stdout, _ = await _run(["container", "image", "ls"], timeout=10)
        snapshots = []
        for line in stdout.strip().split("\n"):
            if SNAPSHOT_PREFIX in line:
                for token in line.split():
                    if token.startswith(SNAPSHOT_PREFIX):
                        snapshots.append(token[len(SNAPSHOT_PREFIX):])
                        break
        return snapshots

    # ── Sandbox management ────────────────────────────────────────────

    async def destroy_sandbox(self, name: str) -> str:
        """Destroy a named sandbox without recreating it."""
        if name not in self._sandboxes:
            return f"Error: no active sandbox '{name}'"
        sb = self._sandboxes[name]
        container = sb.name

        # Stop port forwards and sync jobs targeting this sandbox
        await self._cleanup_forwards_for(name)
        for job_id, job in list(self._sync_jobs.items()):
            if job.sandbox_name == name:
                await self._stop_sync(job_id)

        await sb.destroy()
        del self._sandboxes[name]
        self._save_state()
        log.info(f"Destroyed sandbox '{name}' ({container})")
        return f"Destroyed sandbox '{name}' ({container})"

    async def delete_snapshot(self, snapshot_name: str) -> str:
        """Delete a saved snapshot image."""
        image_name = f"{SNAPSHOT_PREFIX}{snapshot_name}"

        code, stdout, _ = await _run(["container", "image", "ls"], timeout=10)
        if not _output_has_token(stdout, image_name):
            available = await self.list_snapshots()
            avail_str = ", ".join(available) if available else "none"
            return f"Error: snapshot '{snapshot_name}' not found. Available: {avail_str}"

        code, _, stderr = await _run(
            ["container", "image", "rm", image_name], timeout=15
        )
        if code != 0:
            return f"Error deleting snapshot: {stderr.strip()}"

        log.info(f"Deleted snapshot '{snapshot_name}' ({image_name})")
        return f"Deleted snapshot '{snapshot_name}'"

    async def network_info(self) -> dict:
        """Collect IP addresses and connectivity for all sandboxes."""
        info = {}
        for name, sb in self._sandboxes.items():
            try:
                ip = await sb.get_ip()
                info[name] = {
                    "container": sb.name,
                    "ip": ip,
                    "shell": "alive" if sb._shell.is_alive() else "dead",
                }
            except Exception as e:
                info[name] = {"container": sb.name, "ip": None, "error": str(e)}

        # Test pairwise connectivity if multiple sandboxes
        names = list(info.keys())
        if len(names) >= 2:
            for i, src_name in enumerate(names):
                src_ip = info[src_name].get("ip")
                if not src_ip:
                    continue
                peers = {}
                for j, tgt_name in enumerate(names):
                    if i == j:
                        continue
                    tgt_ip = info[tgt_name].get("ip")
                    if not tgt_ip:
                        peers[tgt_name] = "unknown (no ip)"
                        continue
                    sb = self._sandboxes[src_name]
                    result = await sb.exec(
                        f"ping -c 1 -W 1 {_sq(tgt_ip)} >/dev/null 2>&1 && echo ok || echo fail",
                        timeout=5, audit=False,
                    )
                    peers[tgt_name] = result["stdout"].strip()
                info[src_name]["peers"] = peers

        return info

    async def build_image(self, name: str, containerfile: str) -> str:
        """Build a container image from Containerfile content."""
        t0 = time.perf_counter()
        with tempfile.TemporaryDirectory() as tmpdir:
            cf_path = os.path.join(tmpdir, "Containerfile")
            with open(cf_path, "w") as f:
                f.write(containerfile)

            code, stdout, stderr = await _run(
                ["container", "build", "-t", name, tmpdir],
                timeout=300,
            )
            if code != 0:
                return f"Error building image: {stderr.strip()}"

        elapsed = (time.perf_counter() - t0) * 1000
        return f"Built image '{name}' ({elapsed:.0f}ms)"

    async def list_images(self) -> str:
        """List all container images with size info."""
        code, stdout, stderr = await _run(["container", "image", "ls"], timeout=10)
        if code != 0:
            return f"Error listing images: {stderr.strip()}"
        return stdout.strip() if stdout.strip() else "No images found"

    async def check_image(self) -> bool:
        """Check if the configured default image exists."""
        code, stdout, _ = await _run(["container", "image", "ls"], timeout=10)
        return _output_has_token(stdout, self.image) if code == 0 else False

    # ── Port forwarding ──────────────────────────────────────────────

    async def expose(self, host_port: int, container_port: int, sandbox_name: str) -> str:
        """Create a localhost TCP forwarder to a sandbox port."""
        if host_port in self._port_forwards:
            pf = self._port_forwards[host_port]
            return (
                f"Error: localhost:{host_port} already forwarding to "
                f"'{pf.sandbox_name}':{pf.container_port}. "
                f"Use sandbox_unexpose({host_port}) first."
            )

        if sandbox_name not in self._sandboxes:
            # Ensure sandbox exists
            await self.get_sandbox(sandbox_name)

        sb = self._sandboxes[sandbox_name]

        # Check if container port is listening
        result = await sb.exec(
            f"nc -z 127.0.0.1 {int(container_port)} 2>/dev/null && echo open || echo closed",
            timeout=5, audit=False,
        )
        port_status = result["stdout"].strip()

        pf = PortForward(
            host_port=host_port,
            container_port=container_port,
            sandbox_name=sandbox_name,
        )

        async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            pf._connections += 1
            container_name = self._sandboxes.get(sandbox_name)
            if not container_name:
                writer.close()
                return
            container_name = container_name.name

            try:
                proc = await asyncio.create_subprocess_exec(
                    "container", "exec", "-i", container_name,
                    "nc", "127.0.0.1", str(container_port),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                async def client_to_container():
                    try:
                        while True:
                            data = await reader.read(8192)
                            if not data:
                                break
                            proc.stdin.write(data)
                            await proc.stdin.drain()
                    except (asyncio.CancelledError, ConnectionError, BrokenPipeError):
                        pass
                    finally:
                        try:
                            proc.stdin.close()
                        except Exception:
                            pass

                async def container_to_client():
                    try:
                        while True:
                            data = await proc.stdout.read(8192)
                            if not data:
                                break
                            writer.write(data)
                            await writer.drain()
                    except (asyncio.CancelledError, ConnectionError, BrokenPipeError):
                        pass
                    finally:
                        writer.close()

                await asyncio.gather(
                    client_to_container(),
                    container_to_client(),
                    return_exceptions=True,
                )
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

            except Exception as e:
                log.warning(f"Port forward {host_port}->{container_port} connection error: {e}")
                writer.close()

        try:
            server = await asyncio.start_server(
                handle_connection, "127.0.0.1", host_port,
            )
        except OSError as e:
            return f"Error: could not bind localhost:{host_port} — {e}"

        pf._server = server
        self._port_forwards[host_port] = pf
        log.info(f"Port forward: localhost:{host_port} -> '{sandbox_name}':{container_port}")

        warning = ""
        if port_status != "open":
            warning = f"\n  Warning: port {container_port} is not yet listening in the sandbox"

        return (
            f"Forwarding localhost:{host_port} -> '{sandbox_name}':{container_port}\n"
            f"  URL:  http://localhost:{host_port}\n"
            f"  curl: curl http://localhost:{host_port}{warning}"
        )

    async def unexpose(self, host_port: int) -> str:
        """Stop a port forward."""
        if host_port not in self._port_forwards:
            active = ", ".join(str(p) for p in self._port_forwards.keys())
            return f"Error: no forward on localhost:{host_port}. Active: {active or 'none'}"

        pf = self._port_forwards[host_port]
        if pf._server:
            pf._server.close()
            try:
                await pf._server.wait_closed()
            except Exception:
                pass

        del self._port_forwards[host_port]
        log.info(f"Stopped port forward: localhost:{host_port}")
        return (
            f"Stopped forwarding localhost:{host_port} -> "
            f"'{pf.sandbox_name}':{pf.container_port} "
            f"({pf._connections} connections served)"
        )

    async def _cleanup_forwards_for(self, sandbox_name: str):
        """Stop all port forwards for a sandbox."""
        to_remove = [
            hp for hp, pf in self._port_forwards.items()
            if pf.sandbox_name == sandbox_name
        ]
        for hp in to_remove:
            await self.unexpose(hp)

    async def shutdown(self):
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Stop all port forwards
        for hp in list(self._port_forwards.keys()):
            await self.unexpose(hp)

        for job_id in list(self._sync_jobs.keys()):
            await self._stop_sync(job_id)

        for name, sb in list(self._sandboxes.items()):
            await sb.destroy()
        self._sandboxes.clear()
        self._save_state()
        log.info("All sandboxes destroyed")

    async def status(self) -> dict:
        sb_info = {}
        for name, sb in self._sandboxes.items():
            ip = None
            if sb._shell.is_alive():
                try:
                    ip = await sb.get_ip()
                except Exception:
                    pass
            idle_secs = time.time() - sb.last_activity
            cpus, memory, _ = self._get_profile(name)
            sb_info[name] = {
                "container": sb.name,
                "shell": "alive" if sb._shell.is_alive() else "dead",
                "ip": ip,
                "bg_processes": len(sb._bg_processes),
                "idle": f"{idle_secs:.0f}s",
                "cpus": cpus,
                "memory": memory,
                "history": len(sb._audit_log),
            }
        sync_info = {}
        for job_id, job in self._sync_jobs.items():
            sync_info[job_id] = {
                "local": job.local_dir,
                "remote": f"{job.sandbox_name}:{job.sandbox_dir}",
                "files_synced": job.files_synced,
                "running": job.task is not None and not job.task.done(),
            }
        fwd_info = {}
        for hp, pf in self._port_forwards.items():
            fwd_info[hp] = {
                "host_port": pf.host_port,
                "container_port": pf.container_port,
                "sandbox": pf.sandbox_name,
                "connections": pf._connections,
                "uptime": f"{time.time() - pf.started_at:.0f}s",
            }
        return {
            "sandboxes": sb_info,
            "image": self.image,
            "network": "default" if self._network_available else None,
            "sync_jobs": sync_info,
            "port_forwards": fwd_info,
        }


# ── MCP Server ───────────────────────────────────────────────────────────

mcp_server = FastMCP(
    "sandbox",
    instructions=(
        "You have access to isolated Linux sandboxes (Alpine Linux in lightweight VMs). "
        "Use sandbox_exec to run shell commands, sandbox_python for Python code, "
        "sandbox_write_file/sandbox_read_file for file operations, and sandbox_install "
        "to add packages. Each command runs in ~60ms. The sandbox persists across calls "
        "but can be reset to a clean state with sandbox_reset. "
        "Files in /workspace persist across resets (use wipe_workspace=true to clear). "
        "Pre-installed: Python 3, Node.js, Go, Rust, git, curl, build-base. "
        "Use sandbox_upload/sandbox_download to move files between host and sandbox. "
        "Use sandbox_bg to start background processes (servers, watchers) and sandbox_logs to read their output. "
        "Use sandbox_snapshot/sandbox_restore to save and restore sandbox state. "
        "Use sandbox_git_clone to clone repos with optional auth token. "
        "For multi-sandbox workflows, pass sandbox='name' to any tool to target a specific named sandbox. "
        "Package caches (apk/pip/npm) persist across resets for faster reinstalls. "
        "Use sandbox_list to see all sandboxes, sandbox_destroy to kill one permanently. "
        "Use sandbox_expose to forward a sandbox port to localhost (TCP proxy via container exec). "
        "Use sandbox_unexpose to stop a port forward. "
        "Use sandbox_build_image to build custom images from Containerfile content. "
        "Use sandbox_network_info to check inter-sandbox connectivity."
    ),
)

manager = SandboxManager()


# ── Core tools ───────────────────────────────────────────────────────────

@mcp_server.tool()
async def sandbox_exec(
    command: str,
    timeout: float = DEFAULT_TIMEOUT,
    workdir: str = "/workspace",
    stdin: str = "",
    sandbox: str = "default",
) -> str:
    """
    Execute a shell command in the sandbox.

    Args:
        command: Shell command to run (e.g., "ls -la", "echo hello", "cat /etc/os-release")
        timeout: Max seconds to wait (default 30)
        workdir: Working directory inside the sandbox (default /workspace)
        stdin: Optional input to pipe into the command's stdin
        sandbox: Named sandbox to use (default "default")

    Returns:
        Command output with stdout, stderr, exit code, and execution time.
    """
    sb = await manager.get_sandbox(sandbox)
    await sb.ensure_dir(workdir)

    if stdin:
        stdin_path = f"/tmp/_mcp_stdin_{uuid.uuid4().hex[:8]}"
        code, stderr = await sb.write_bytes(stdin_path, stdin.encode(), timeout=min(60.0, max(timeout, 5.0)))
        if code != 0:
            return f"Error preparing stdin: {stderr.strip()}"
        command = f"( {command} ) < {_sq(stdin_path)}"

    result = await manager._exec_with_recovery(sb, command, timeout=timeout, workdir=workdir)

    if stdin:
        # Best-effort cleanup after execution/recovery attempts complete.
        cleanup_target = manager._sandboxes.get(sandbox, sb)
        try:
            await cleanup_target.exec(f"rm -f {_sq(stdin_path)} 2>/dev/null", audit=False)
        except Exception:
            pass

    return _format_result(result)


@mcp_server.tool()
async def sandbox_python(
    code: str,
    timeout: float = DEFAULT_TIMEOUT,
    sandbox: str = "default",
) -> str:
    """
    Execute Python code in the sandbox (python3 is pre-installed in
    the default mcp-dev image).

    Args:
        code: Python code to execute.
        timeout: Max seconds to wait (default 30).
        sandbox: Named sandbox to use (default "default")

    Returns:
        Script output with stdout, stderr, exit code, and execution time.
    """
    sb = await manager.get_sandbox(sandbox)
    write_code, write_err = await sb.write_bytes("/tmp/_mcp_run.py", code.encode(), timeout=60)
    if write_code != 0:
        return f"Error writing script: {write_err.strip()}"
    cmd = "python3 /tmp/_mcp_run.py"
    result = await manager._exec_with_recovery(sb, cmd, timeout=timeout)
    return _format_result(result)


@mcp_server.tool()
async def sandbox_write_file(
    path: str,
    content: str,
    sandbox: str = "default",
) -> str:
    """
    Write content to a file in the sandbox.

    Args:
        path: Absolute path in the sandbox (e.g., /workspace/script.py)
        content: File content to write.
        sandbox: Named sandbox to use (default "default")

    Returns:
        Confirmation with file path and size.
    """
    sb = await manager.get_sandbox(sandbox)
    data = content.encode()
    code, stderr = await sb.write_bytes(path, data, timeout=60)
    if code != 0:
        return f"Error: {stderr.strip()}"
    return f"Wrote {len(data)} bytes to {path}"


@mcp_server.tool()
async def sandbox_read_file(
    path: str,
    sandbox: str = "default",
) -> str:
    """
    Read a file from the sandbox.

    Args:
        path: Absolute path to read (e.g., /workspace/output.txt)
        sandbox: Named sandbox to use (default "default")

    Returns:
        File contents.
    """
    sb = await manager.get_sandbox(sandbox)
    result = await manager._exec_with_recovery(sb, f"cat {_sq(path)}")
    if result["exit_code"] == 0:
        return result["stdout"]
    return f"Error: {result['stderr']}"


@mcp_server.tool()
async def sandbox_install(
    packages: str,
    sandbox: str = "default",
) -> str:
    """
    Install packages in the sandbox using apk (Alpine package manager).

    Args:
        packages: Space-separated package names (e.g., "python3 nodejs git curl")
        sandbox: Named sandbox to use (default "default")

    Returns:
        Installation result.
    """
    sb = await manager.get_sandbox(sandbox)
    result = await manager._exec_with_recovery(
        sb, f"apk add --no-cache {packages}", timeout=120
    )
    if result["exit_code"] == 0:
        lines = result["stdout"].strip().split("\n")
        installed = [
            ln for ln in lines
            if ln.startswith("OK:") or "Installing" in ln or "installing" in ln.lower()
        ]
        summary = "\n".join(installed[-5:]) if installed else f"Installed {packages}"
        return f"{summary}\n({result['duration_ms']}ms)"
    return f"Error: {result['stderr']}\n({result['duration_ms']}ms)"


@mcp_server.tool()
async def sandbox_reset(
    wipe_workspace: bool = False,
    sandbox: str = "default",
) -> str:
    """
    Destroy the current sandbox and create a fresh one.
    Use this when you want a clean environment.

    Args:
        wipe_workspace: If True, also delete all files in /workspace.
                        If False (default), /workspace files persist across resets.
        sandbox: Named sandbox to reset (default "default")

    Returns:
        Confirmation of the new sandbox.
    """
    return await manager.reset(name=sandbox, wipe_workspace=wipe_workspace)


@mcp_server.tool()
async def sandbox_status() -> str:
    """
    Show current sandbox and pool status.

    Returns:
        Status information including active sandboxes, pool size, image, and network.
    """
    status = await manager.status()

    lines = []

    sb_info = status["sandboxes"]
    if sb_info:
        for name, info in sb_info.items():
            parts = [
                f"  {name:12s} {info['container']}",
                f"shell:{info['shell']}",
            ]
            if info.get("ip"):
                parts.append(f"ip:{info['ip']}")
            if info["bg_processes"] > 0:
                parts.append(f"bg:{info['bg_processes']}")
            parts.append(f"idle:{info['idle']}")
            parts.append(f"{info['cpus']}cpu/{info['memory']}")
            if info["history"] > 0:
                parts.append(f"cmds:{info['history']}")
            lines.append("  ".join(parts))
    else:
        lines.append("No active sandboxes (boot on first use)")

    lines.append(f"Image:    {status['image']}")
    lines.append(f"Volumes:  per-sandbox (workspace + apk/pip/npm caches)")

    if status.get("network"):
        lines.append(f"Network:  {status['network']}")

    if SANDBOX_PROFILES:
        profile_parts = [
            f"{k}({v.get('cpus', SANDBOX_CPUS)}cpu/{v.get('memory', SANDBOX_MEMORY)})"
            for k, v in SANDBOX_PROFILES.items()
        ]
        lines.append(f"Profiles: {', '.join(profile_parts)}")

    fwd_info = status.get("port_forwards", {})
    if fwd_info:
        lines.append("Port forwards:")
        for hp, info in fwd_info.items():
            lines.append(
                f"  localhost:{info['host_port']} -> "
                f"'{info['sandbox']}':{info['container_port']} "
                f"({info['connections']} conns, up {info['uptime']})"
            )

    sync_info = status.get("sync_jobs", {})
    if sync_info:
        lines.append("Sync jobs:")
        for job_id, info in sync_info.items():
            state = "running" if info["running"] else "stopped"
            lines.append(
                f"  {job_id}: {info['local']} -> {info['remote']} "
                f"({info['files_synced']} files, {state})"
            )

    return "\n".join(lines)


@mcp_server.tool()
async def sandbox_health() -> str:
    """
    Quick health check across all sandboxes: shell liveness, disk/memory pressure, uptime.
    Useful for diagnosing issues when commands fail or sandboxes become unresponsive.

    Returns:
        Per-sandbox health summary with warnings for any issues detected.
    """
    if not manager._sandboxes:
        return "No active sandboxes"

    lines = []
    issues = 0
    for name, sb in manager._sandboxes.items():
        parts = [f"{name}:"]

        # Shell liveness
        alive = sb._shell.is_alive()
        parts.append(f"shell={'ok' if alive else 'DEAD'}")
        if not alive:
            issues += 1

        if alive:
            # Disk pressure
            disk = await sb.exec(
                "df /workspace 2>/dev/null | awk 'NR==2{print $5}'",
                timeout=5, audit=False,
            )
            disk_pct = disk["stdout"].strip().rstrip("%")
            if disk_pct.isdigit():
                pct = int(disk_pct)
                label = "FULL" if pct >= 95 else ("HIGH" if pct >= 80 else "ok")
                parts.append(f"disk={pct}%{'' if label == 'ok' else ' ' + label}")
                if pct >= 80:
                    issues += 1
            # Memory pressure
            mem = await sb.exec(
                "awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{if(t>0)printf \"%.0f\",(t-a)/t*100}' /proc/meminfo",
                timeout=5, audit=False,
            )
            mem_pct = mem["stdout"].strip()
            if mem_pct.isdigit():
                pct = int(mem_pct)
                label = "OOM" if pct >= 95 else ("HIGH" if pct >= 80 else "ok")
                parts.append(f"mem={pct}%{'' if label == 'ok' else ' ' + label}")
                if pct >= 80:
                    issues += 1

            # Uptime
            up = await sb.exec("awk '{printf \"%.0f\",$1}' /proc/uptime", timeout=5, audit=False)
            up_s = up["stdout"].strip()
            if up_s.isdigit():
                m, s = divmod(int(up_s), 60)
                parts.append(f"up={m}m{s}s")

            # Process count
            ps = await sb.exec("ls -1d /proc/[0-9]* 2>/dev/null | wc -l", timeout=5, audit=False)
            parts.append(f"procs={ps['stdout'].strip()}")

        # Port forwards
        fwds = [pf for pf in manager._port_forwards.values() if pf.sandbox_name == name]
        if fwds:
            ports = ",".join(f"{pf.host_port}->{pf.container_port}" for pf in fwds)
            parts.append(f"fwd=[{ports}]")

        lines.append("  ".join(parts))

    summary = f"{len(manager._sandboxes)} sandbox(es), {issues} issue(s)"
    return summary + "\n" + "\n".join(lines)


# ── File transfer tools ──────────────────────────────────────────────────

@mcp_server.tool()
async def sandbox_upload(
    local_path: str,
    sandbox_path: str = "/workspace",
    sandbox: str = "default",
) -> str:
    """
    Copy a file or directory from the host into the sandbox.

    Args:
        local_path: Absolute path on the host (file or directory).
        sandbox_path: Destination path inside the sandbox (default: /workspace).
        sandbox: Named sandbox to use (default "default")

    Returns:
        Confirmation with transferred file count and size.
    """
    local_path = os.path.expanduser(local_path)
    if not os.path.exists(local_path):
        return f"Error: {local_path} does not exist on host"

    sb = await manager.get_sandbox(sandbox)
    await sb.ensure_dir(sandbox_path)

    t0 = time.perf_counter()

    if os.path.isfile(local_path):
        with open(local_path, "rb") as f:
            data = f.read()
        filename = os.path.basename(local_path)
        dest = f"{sandbox_path}/{filename}" if not sandbox_path.endswith(filename) else sandbox_path
        code, stderr = await sb.write_bytes(dest, data, timeout=120)
        if code != 0:
            return f"Error: {stderr.strip()}"
        elapsed = (time.perf_counter() - t0) * 1000
        size = _humanize_bytes(len(data))
        return f"Uploaded {local_path} -> {dest} ({size}, {elapsed:.0f}ms)"
    else:
        tar_proc = await asyncio.create_subprocess_exec(
            "tar", "-cf", "-", "-C", local_path, ".",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        tar_data, tar_err = await tar_proc.communicate()
        if tar_proc.returncode != 0:
            return f"Error creating tar: {tar_err.decode(errors='replace')}"

        cmd = ["container", "exec", "-i", sb.name, "sh", "-c", f"tar -xf - -C {_sq(sandbox_path)}"]
        code, _, stderr = await _run(cmd, timeout=60, input_data=tar_data)
        if code != 0:
            return f"Error extracting in sandbox: {stderr}"

        elapsed = (time.perf_counter() - t0) * 1000
        size = _humanize_bytes(len(tar_data))
        count_result = await sb.exec(f"find {_sq(sandbox_path)} -type f | wc -l", audit=False)
        file_count = count_result["stdout"].strip()
        return f"Uploaded {local_path}/ -> {sandbox_path} ({file_count} files, {size} tar, {elapsed:.0f}ms)"


@mcp_server.tool()
async def sandbox_download(
    sandbox_path: str,
    local_path: str,
    sandbox: str = "default",
) -> str:
    """
    Copy a file or directory from the sandbox to the host.

    Args:
        sandbox_path: Path inside the sandbox to download.
        local_path: Absolute destination path on the host.
        sandbox: Named sandbox to use (default "default")

    Returns:
        Confirmation with transferred size.
    """
    local_path = os.path.expanduser(local_path)
    sb = await manager.get_sandbox(sandbox)
    t0 = time.perf_counter()

    check = await sb.exec(
        f"test -f {_sq(sandbox_path)} && echo file || (test -d {_sq(sandbox_path)} && echo dir || echo missing)",
        audit=False,
    )
    kind = check["stdout"].strip()

    if kind == "missing":
        return f"Error: {sandbox_path} does not exist in sandbox"

    if kind == "file":
        code, raw_stdout, raw_stderr = await sb.exec_raw(
            f"base64 {_sq(sandbox_path)}", timeout=30
        )
        if code != 0:
            return f"Error: {raw_stderr.decode(errors='replace')}"
        data = base64.b64decode(raw_stdout.strip())
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
        with open(local_path, "wb") as f:
            f.write(data)
        elapsed = (time.perf_counter() - t0) * 1000
        return f"Downloaded {sandbox_path} -> {local_path} ({_humanize_bytes(len(data))}, {elapsed:.0f}ms)"
    else:
        code, tar_data, tar_err = await sb.exec_raw(
            f"tar -cf - -C {_sq(sandbox_path)} .", timeout=60
        )
        if code != 0:
            return f"Error: {tar_err.decode(errors='replace')}"
        os.makedirs(local_path, exist_ok=True)
        extract = await asyncio.create_subprocess_exec(
            "tar", "-xf", "-", "-C", local_path,
            stdin=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, extract_err = await extract.communicate(input=tar_data)
        if extract.returncode != 0:
            return f"Error extracting: {extract_err.decode(errors='replace')}"
        elapsed = (time.perf_counter() - t0) * 1000
        return f"Downloaded {sandbox_path}/ -> {local_path} ({_humanize_bytes(len(tar_data))} tar, {elapsed:.0f}ms)"


# ── Background process management ────────────────────────────────────────

@mcp_server.tool()
async def sandbox_bg(
    command: str,
    name: str = "",
    workdir: str = "/workspace",
    sandbox: str = "default",
) -> str:
    """
    Start a background process in the sandbox (e.g., a dev server).

    Args:
        command: Command to run in background (e.g., "python3 -m http.server 8000")
        name: Optional friendly name for the process (auto-generated if empty)
        workdir: Working directory (default: /workspace)
        sandbox: Named sandbox to use (default "default")

    Returns:
        Process ID and name for use with sandbox_logs/sandbox_kill.
    """
    sb = await manager.get_sandbox(sandbox)
    proc_id = name or f"bg-{uuid.uuid4().hex[:6]}"
    log_file = f"/tmp/_mcp_bg_{proc_id}.log"

    bg_cmd = f"cd {_sq(workdir)} && nohup sh -c {_sq(command)} > {_sq(log_file)} 2>&1 & echo $!"
    result = await sb.exec(bg_cmd)

    if result["exit_code"] != 0:
        return f"Error starting background process: {result['stderr']}"

    pid = result["stdout"].strip()
    sb._bg_processes[proc_id] = BgProcess(pid=pid, command=command[:200], log_file=log_file)

    ip = await sb.get_ip()
    lines = [f"Started [{proc_id}] PID {pid}"]
    if ip:
        lines.append(f"Network: accessible at {ip}")
    lines.append(f"Use sandbox_logs('{proc_id}') to read output, sandbox_kill('{proc_id}') to stop.")
    return "\n".join(lines)


@mcp_server.tool()
async def sandbox_logs(
    name: str,
    tail: int = 50,
    sandbox: str = "default",
) -> str:
    """
    Read output from a background process.

    Args:
        name: Process name/ID from sandbox_bg.
        tail: Number of lines to show from end (default: 50, use 0 for all).
        sandbox: Named sandbox to use (default "default")

    Returns:
        Process output (stdout + stderr combined).
    """
    sb = await manager.get_sandbox(sandbox)

    if name not in sb._bg_processes:
        available = ", ".join(sb._bg_processes.keys()) if sb._bg_processes else "none"
        return f"Error: no background process '{name}' in sandbox '{sandbox}'. Running: {available}"

    proc = sb._bg_processes[name]

    alive_check = await sb.exec(f"kill -0 {proc.pid} 2>/dev/null && echo alive || echo dead", audit=False)
    status = alive_check["stdout"].strip()

    if tail > 0:
        result = await sb.exec(f"tail -n {tail} {_sq(proc.log_file)} 2>/dev/null || echo '(no output yet)'", audit=False)
    else:
        result = await sb.exec(f"cat {_sq(proc.log_file)} 2>/dev/null || echo '(no output yet)'", audit=False)

    header = f"[{name}] PID {proc.pid} ({status}) — {proc.command}"
    return f"{header}\n{'─' * 40}\n{result['stdout']}"


@mcp_server.tool()
async def sandbox_kill(
    name: str,
    sandbox: str = "default",
) -> str:
    """
    Kill a background process.

    Args:
        name: Process name/ID from sandbox_bg.
        sandbox: Named sandbox to use (default "default")

    Returns:
        Confirmation.
    """
    sb = await manager.get_sandbox(sandbox)

    if name not in sb._bg_processes:
        available = ", ".join(sb._bg_processes.keys()) if sb._bg_processes else "none"
        return f"Error: no background process '{name}' in sandbox '{sandbox}'. Running: {available}"

    proc = sb._bg_processes[name]

    await sb.exec(f"kill {proc.pid} 2>/dev/null; kill -9 {proc.pid} 2>/dev/null", audit=False)

    result = await sb.exec(f"tail -n 20 {_sq(proc.log_file)} 2>/dev/null", audit=False)
    final_output = result["stdout"].strip()

    del sb._bg_processes[name]

    lines = [f"Killed [{name}] PID {proc.pid}"]
    if final_output:
        lines.append(f"Last output:\n{final_output}")
    return "\n".join(lines)


# ── Execution stats ──────────────────────────────────────────────────────

@mcp_server.tool()
async def sandbox_stats(sandbox: str = "default") -> str:
    """
    Show resource usage (CPU, memory, disk) of the active sandbox.

    Args:
        sandbox: Named sandbox to check (default "default")

    Returns:
        Current resource usage statistics.
    """
    sb = await manager.get_sandbox(sandbox)

    code, stdout, stderr = await _run(
        ["container", "stats", "--no-stream", "--format", "json", sb.name],
        timeout=10,
    )

    disk_result = await sb.exec(
        "df -h /workspace 2>/dev/null | tail -1 | awk '{print $3\"/\"$2\" (\"$5\" used)\"}'",
        audit=False,
    )
    uptime_result = await sb.exec(
        "cat /proc/uptime 2>/dev/null | awk '{printf \"%.0f\", $1}'",
        audit=False,
    )

    cpus, memory, _ = manager._get_profile(sandbox)
    lines = [f"Sandbox: {sb.name} ('{sandbox}', {cpus}cpu/{memory})"]

    if code == 0 and stdout.strip():
        try:
            raw = json.loads(stdout)
            s = raw[0] if isinstance(raw, list) else raw
            mem_used = s.get("memoryUsageBytes", 0)
            mem_limit = s.get("memoryLimitBytes", 0)
            cpu_usec = s.get("cpuUsageUsec", 0)
            net_rx = s.get("networkRxBytes", 0)
            net_tx = s.get("networkTxBytes", 0)
            blk_r = s.get("blockReadBytes", 0)
            blk_w = s.get("blockWriteBytes", 0)
            pids = s.get("numProcesses", 0)
            mem_pct = (mem_used / mem_limit * 100) if mem_limit else 0
            lines.append(f"Memory:  {_humanize_bytes(mem_used)} / {_humanize_bytes(mem_limit)} ({mem_pct:.0f}%)")
            lines.append(f"CPU:     {cpu_usec / 1_000_000:.2f}s total")
            lines.append(f"Net:     {_humanize_bytes(net_rx)} rx / {_humanize_bytes(net_tx)} tx")
            lines.append(f"Block:   {_humanize_bytes(blk_r)} read / {_humanize_bytes(blk_w)} write")
            lines.append(f"PIDs:    {pids}")
        except (json.JSONDecodeError, KeyError, IndexError):
            lines.append(f"Stats:   {stdout.strip()}")
    else:
        mem_result = await sb.exec(
            "cat /proc/meminfo | awk '/MemTotal/{t=$2}/MemAvail/{a=$2}END{printf \"%dMB / %dMB\", (t-a)/1024, t/1024}'",
            audit=False,
        )
        lines.append(f"Memory:  {mem_result['stdout'] or 'N/A'}")

    disk = disk_result["stdout"].strip()
    if disk:
        lines.append(f"Disk:    {disk}")

    ip = await sb.get_ip()
    if ip:
        lines.append(f"IP:      {ip}")

    uptime_s = uptime_result["stdout"].strip()
    if uptime_s and uptime_s.isdigit():
        mins = int(uptime_s) // 60
        secs = int(uptime_s) % 60
        lines.append(f"Uptime:  {mins}m {secs}s")

    if sb._bg_processes:
        lines.append(f"BgProcs: {', '.join(sb._bg_processes.keys())}")

    lines.append(f"History: {len(sb._audit_log)} commands")

    return "\n".join(lines)


# ── Snapshot tools ───────────────────────────────────────────────────────

@mcp_server.tool()
async def sandbox_snapshot(
    snapshot_name: str,
    sandbox: str = "default",
) -> str:
    """
    Save the current sandbox state as a reusable snapshot image.
    The snapshot captures installed packages and system state (not /workspace files,
    which live on a separate persistent volume).

    Args:
        snapshot_name: Name for the snapshot (e.g., "with-pytorch", "ml-env")
        sandbox: Named sandbox to snapshot (default "default")

    Returns:
        Confirmation or error.
    """
    return await manager.snapshot(snapshot_name, sandbox_name=sandbox)


@mcp_server.tool()
async def sandbox_restore(
    snapshot_name: str,
    sandbox: str = "default",
) -> str:
    """
    Destroy the current sandbox and boot from a saved snapshot.
    Workspace files are preserved (they live on a separate volume).

    Args:
        snapshot_name: Name of the snapshot to restore (from sandbox_list_snapshots)
        sandbox: Named sandbox to restore into (default "default")

    Returns:
        Confirmation or error.
    """
    return await manager.restore(snapshot_name, sandbox_name=sandbox)


@mcp_server.tool()
async def sandbox_list_snapshots() -> str:
    """
    List all available sandbox snapshots.

    Returns:
        List of snapshot names, or "none" if no snapshots exist.
    """
    snapshots = await manager.list_snapshots()
    if not snapshots:
        return "No snapshots saved. Use sandbox_snapshot('name') to create one."
    return "Available snapshots:\n" + "\n".join(f"  - {s}" for s in snapshots)


# ── Git clone tool ───────────────────────────────────────────────────────

@mcp_server.tool()
async def sandbox_git_clone(
    repo: str,
    branch: str = "",
    token: str = "",
    path: str = "/workspace",
    shallow: bool = True,
    sandbox: str = "default",
) -> str:
    """
    Clone a git repository into the sandbox.

    Args:
        repo: Repository URL (e.g., "https://github.com/user/repo.git")
        branch: Branch to clone (default: repo's default branch)
        token: Optional auth token for private repos (injected securely, not in URL or history)
        path: Parent directory for clone (default: /workspace)
        shallow: If True, clone with --depth 1 for speed (default: True)
        sandbox: Named sandbox to use (default "default")

    Returns:
        Clone result with repo info.
    """
    sb = await manager.get_sandbox(sandbox)

    repo_name = repo.rstrip("/").split("/")[-1].replace(".git", "")
    clone_path = f"{path}/{repo_name}"

    clone_args = ""
    if shallow:
        clone_args += " --depth 1"
    if branch:
        clone_args += f" --branch {_sq(branch)}"

    if token:
        helper_script = f'#!/bin/sh\nprintf "username=x-access-token\\n"\nprintf "password=%s\\n" {_sq(token)}'
        write_code, write_err = await sb.write_bytes("/tmp/.git-cred", helper_script.encode(), timeout=30)
        if write_code != 0:
            return f"Error preparing credentials: {write_err.strip()}"

        chmod_result = await manager._exec_with_recovery(
            sb, "chmod 700 /tmp/.git-cred", timeout=20, audit=False
        )
        if chmod_result["exit_code"] != 0:
            await manager._exec_with_recovery(sb, "rm -f /tmp/.git-cred", timeout=10, audit=False)
            return f"Error preparing credentials: {chmod_result['stderr']}\n({chmod_result['duration_ms']}ms)"

        clone_cmd = f"git -c credential.helper=/tmp/.git-cred clone{clone_args} {_sq(repo)} {_sq(clone_path)}"
        try:
            # Avoid writing token-bearing command fragments to command history.
            result = await manager._exec_with_recovery(sb, clone_cmd, timeout=120, audit=False)
        finally:
            try:
                await manager._exec_with_recovery(sb, "rm -f /tmp/.git-cred", timeout=10, audit=False)
            except Exception:
                pass
    else:
        cmd = f"GIT_TERMINAL_PROMPT=0 git clone{clone_args} {_sq(repo)} {_sq(clone_path)}"
        result = await manager._exec_with_recovery(sb, cmd, timeout=120)

    if result["exit_code"] == 0:
        info = await sb.exec(
            f"cd {_sq(clone_path)} && echo \"$(git log --oneline -1)\" && echo \"$(find . -type f | wc -l) files\"",
            audit=False,
        )
        return f"Cloned {repo} -> {clone_path}\n{info['stdout'].strip()}\n({result['duration_ms']}ms)"
    return f"Error cloning: {result['stderr']}\n({result['duration_ms']}ms)"


# ── File sync tools ──────────────────────────────────────────────────────

@mcp_server.tool()
async def sandbox_sync_start(
    local_dir: str,
    sandbox_dir: str = "/workspace",
    sandbox: str = "default",
) -> str:
    """
    Start watching a local host directory and live-syncing changes into the sandbox.
    Does an initial full sync, then polls for changes every second.
    Ignores .git, node_modules, __pycache__, .venv, .DS_Store.

    Args:
        local_dir: Absolute path on the host to watch.
        sandbox_dir: Destination directory in the sandbox (default: /workspace).
        sandbox: Named sandbox to sync to (default "default")

    Returns:
        Sync job ID and initial sync stats.
    """
    return await manager.start_sync(local_dir, sandbox_dir, sandbox_name=sandbox)


@mcp_server.tool()
async def sandbox_sync_stop(
    job_id: str,
) -> str:
    """
    Stop a running file sync job.

    Args:
        job_id: The sync job ID from sandbox_sync_start.

    Returns:
        Confirmation with total files synced.
    """
    return await manager._stop_sync(job_id)


# ── Environment / clone / history / batch tools ──────────────────────────

@mcp_server.tool()
async def sandbox_env(
    action: str = "list",
    key: str = "",
    value: str = "",
    sandbox: str = "default",
) -> str:
    """
    Manage persistent environment variables in a sandbox.
    Variables persist across all commands (sourced from /etc/profile.d/mcp-env.sh).

    Args:
        action: "set", "unset", or "list" (default: "list")
        key: Variable name (required for set/unset)
        value: Variable value (required for set)
        sandbox: Named sandbox (default "default")

    Returns:
        Current env vars or confirmation.
    """
    if action == "set":
        if not key:
            return "Error: key is required for set"
        return await manager.set_env(sandbox, key, value)
    elif action == "unset":
        if not key:
            return "Error: key is required for unset"
        return await manager.unset_env(sandbox, key)
    else:
        env_content = await manager.get_env(sandbox)
        if not env_content:
            return "No persistent env vars set. Use sandbox_env(action='set', key='FOO', value='bar')."
        return f"Persistent env vars in '{sandbox}':\n{env_content}"


@mcp_server.tool()
async def sandbox_clone(
    source: str,
    target: str,
) -> str:
    """
    Clone a running sandbox to a new name.
    Copies the full filesystem (except /workspace) to a fresh sandbox.
    Faster than snapshot+restore since it skips image build.

    Args:
        source: Name of the sandbox to clone from.
        target: Name for the new cloned sandbox.

    Returns:
        Confirmation with timing.
    """
    return await manager.clone(source, target)


@mcp_server.tool()
async def sandbox_history(
    limit: int = 20,
    sandbox: str = "default",
) -> str:
    """
    Show recent command history for a sandbox.
    Tracks the last 100 commands with exit codes and timing.

    Args:
        limit: Number of recent commands to show (default: 20)
        sandbox: Named sandbox (default "default")

    Returns:
        Command history with timing and exit codes.
    """
    entries = manager.get_history(sandbox, limit=limit)
    if not entries:
        return f"No command history for '{sandbox}'."

    lines = [f"Recent commands in '{sandbox}' ({len(entries)} shown):"]
    for i, e in enumerate(entries, 1):
        status = "ok" if e["exit_code"] == 0 else f"exit:{e['exit_code']}"
        lines.append(f"  {i:2d}. [{status}] {e['duration_ms']:.0f}ms {e['ago']} ago  {e['command']}")
    return "\n".join(lines)


@mcp_server.tool()
async def sandbox_batch_write(
    files: str,
    sandbox: str = "default",
) -> str:
    """
    Write multiple files to the sandbox in a single operation.
    Much faster than multiple sandbox_write_file calls for scaffolding projects.

    Args:
        files: JSON object mapping absolute paths to file contents.
               Example: {"/workspace/main.py": "print('hi')", "/workspace/config.yml": "port: 8080"}
        sandbox: Named sandbox (default "default")

    Returns:
        Confirmation with file count and timing.
    """
    try:
        file_map = json.loads(files)
    except json.JSONDecodeError as e:
        return f"Error: invalid JSON — {e}"

    if not isinstance(file_map, dict):
        return "Error: files must be a JSON object mapping paths to contents"

    return await manager.write_files(sandbox, file_map)


# ── Lifecycle / snapshot / networking tools ──────────────────────────────

@mcp_server.tool()
async def sandbox_list() -> str:
    """
    List all active sandboxes with their status.

    Returns:
        Table of sandbox names, containers, shell status, and idle time.
    """
    await manager.ensure_started()
    if not manager._sandboxes:
        return "No active sandboxes. Use any sandbox tool to auto-create 'default'."

    lines = [f"{'Name':12s}  {'Container':16s}  {'Shell':6s}  {'Idle':>8s}  {'Resources'}"]
    lines.append("─" * 65)
    for name, sb in manager._sandboxes.items():
        shell = "alive" if sb._shell.is_alive() else "dead"
        idle = f"{time.time() - sb.last_activity:.0f}s"
        cpus, memory, _ = manager._get_profile(name)
        lines.append(f"{name:12s}  {sb.name:16s}  {shell:6s}  {idle:>8s}  {cpus}cpu/{memory}")
    return "\n".join(lines)


@mcp_server.tool()
async def sandbox_destroy(sandbox: str) -> str:
    """
    Permanently destroy a named sandbox without recreating it.
    Unlike sandbox_reset (which destroys and reboots), this just kills it.
    Workspace volume is preserved and will be reattached if the sandbox is recreated.

    Args:
        sandbox: Name of the sandbox to destroy.

    Returns:
        Confirmation or error.
    """
    return await manager.destroy_sandbox(sandbox)


@mcp_server.tool()
async def sandbox_delete_snapshot(snapshot_name: str) -> str:
    """
    Delete a saved snapshot image. Frees disk space.

    Args:
        snapshot_name: Name of the snapshot to delete (from sandbox_list_snapshots).

    Returns:
        Confirmation or error.
    """
    return await manager.delete_snapshot(snapshot_name)


@mcp_server.tool()
async def sandbox_network_info() -> str:
    """
    Show network information for all sandboxes including IP addresses
    and pairwise connectivity. Useful for multi-sandbox workflows
    where services need to communicate.

    Returns:
        Network info with IPs and connectivity status.
    """
    info = await manager.network_info()
    if not info:
        return "No active sandboxes."

    lines = []
    for name, data in info.items():
        ip = data.get("ip") or "unknown"
        shell = data.get("shell", "unknown")
        lines.append(f"{name:12s}  {data['container']}  ip:{ip}  shell:{shell}")
        peers = data.get("peers", {})
        for peer_name, status in peers.items():
            icon = "ok" if status == "ok" else "FAIL"
            lines.append(f"  -> {peer_name}: {icon}")

    return "\n".join(lines)


@mcp_server.tool()
async def sandbox_build_image(
    name: str,
    containerfile: str,
) -> str:
    """
    Build a container image from a Containerfile (Dockerfile syntax).
    The image can then be used with sandbox_restore or as the default image.

    Args:
        name: Name/tag for the built image (e.g., "my-ml-env", "node-app").
        containerfile: Containerfile content (Dockerfile syntax).
                       Example: "FROM alpine:3.23\\nRUN apk add --no-cache python3"

    Returns:
        Confirmation with build time.
    """
    return await manager.build_image(name, containerfile)


@mcp_server.tool()
async def sandbox_images() -> str:
    """
    List all available container images (base images + snapshots + custom builds).

    Returns:
        Image listing with names and sizes.
    """
    return await manager.list_images()


@mcp_server.tool()
async def sandbox_expose(
    port: int,
    host_port: int = 0,
    sandbox: str = "default",
) -> str:
    """
    Forward a sandbox port to localhost via TCP proxy.
    Creates a local listener that proxies connections into the sandbox via `container exec`.

    Args:
        port: Port number inside the sandbox (e.g., 8000, 3000, 5432).
        host_port: Port to listen on locally (default: same as sandbox port).
        sandbox: Named sandbox to expose (default "default").

    Returns:
        Connection URL if successful, or error message.
    """
    hp = host_port if host_port > 0 else port
    return await manager.expose(hp, int(port), sandbox)


@mcp_server.tool()
async def sandbox_unexpose(
    port: int,
) -> str:
    """
    Stop a port forward previously created by sandbox_expose.

    Args:
        port: The localhost port to stop forwarding.

    Returns:
        Confirmation with connection stats.
    """
    return await manager.unexpose(int(port))


# ── Result formatter ─────────────────────────────────────────────────────

def _format_result(result: dict) -> str:
    """Format exec result for LLM consumption."""
    parts = []
    if result["stdout"]:
        parts.append(result["stdout"])
    if result["stderr"]:
        parts.append(f"[stderr] {result['stderr']}")
    if result["exit_code"] != 0:
        parts.append(f"[exit code {result['exit_code']}]")
    parts.append(f"({result['duration_ms']}ms)")
    return "\n".join(parts)


# ── Entry point ──────────────────────────────────────────────────────────

def main():
    mcp_server.run(transport="stdio")


if __name__ == "__main__":
    main()
