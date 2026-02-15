# sandbox-mcp [![CI](https://github.com/bird/sandbox-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/bird/sandbox-mcp/actions/workflows/ci.yml)

Local AI agent sandbox. Run isolated Linux VMs on your Mac in ~60ms. No cloud costs. VM-level isolation via Virtualization.framework. Works with MCP clients that support local stdio servers (Claude Code, Claude Desktop, Cursor).

## What this is

An MCP server that gives AI agents a sandboxed Linux environment using [Apple Containerization](https://github.com/apple/containerization) (Virtualization.framework). Each sandbox is a real VM — not a container sharing your kernel — that boots in ~700ms and executes commands in ~60ms via a persistent shell over vsock.

**Compared to cloud sandboxes (as of early 2025):**

| | Exec latency | Cost | Isolation |
|---|---|---|---|
| **This (local)** | ~60ms | Local hardware | VM (Virtualization.framework) |
| E2B | ~150ms + network | $0.18/hr | Firecracker microVM |
| Daytona | ~90ms + network | Usage-based | Docker container |

## Quick demo

Once registered, your MCP client can use the sandbox tools directly:

```
Agent: exec(command="uname -a")
→ Linux mcp-sb-abc123 6.12.6 #1 SMP aarch64 Linux

Agent: install(packages="python3 py3-pip")
→ Installed python3 py3-pip (1230ms)

Agent: exec(command="python3 -c 'print(sum(range(1000)))'")
→ 499500

Agent: bg(command="python3 -m http.server 8000")
→ Started [bg-a1b2c3] PID 42

Agent: expose(port=8000)
→ Forwarding localhost:8000 → 'default':8000
  Open http://localhost:8000
```

Cold boot is ~700ms, subsequent commands ~60ms each.

## Requirements

- Apple Silicon Mac (M1+)
- macOS 15 Sequoia+
- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (for packaging)

## Setup

### 1. Install Apple Containers

```bash
# Download and install the container CLI
curl -LO https://github.com/apple/containerization/releases/download/v0.9.0/container-v0.9.0.pkg
sudo installer -pkg container-v0.9.0.pkg -target /

# Start the container system (downloads kernel on first run)
container system start

# Verify it works
time container run --rm alpine echo "hello"  # ~700ms cold boot
```

### 2. Build the dev image

The included `Containerfile.mcp-dev` builds an Alpine image pre-loaded with Python, Node.js, Go, Rust, and standard build tools:

```bash
cd sandbox-mcp
container build -t mcp-dev -f Containerfile.mcp-dev .
```

### 3. Install the MCP server

```bash
uv sync
```

### 4. Register with your MCP client

**Claude Code:**
```bash
claude mcp add sandbox -- uv --directory /path/to/sandbox-mcp run sandbox-mcp
```

**Manual (`~/.claude.json`):**
```json
{
  "mcpServers": {
    "sandbox": {
      "type": "stdio",
      "command": "/path/to/uv",
      "args": ["--directory", "/path/to/sandbox-mcp", "run", "sandbox-mcp"]
    }
  }
}
```

### 5. Building the optimized kernel (optional)

Apple's containerization repo includes a stripped-down Linux kernel config. Compiling it yourself doesn't meaningfully improve exec latency — the ~700ms floor is VM lifecycle overhead (Virtualization.framework + EXT4 + network + vminitd), not kernel boot. The real win is keeping VMs warm and using persistent shell exec (~60ms).

That said, if you want a smaller kernel:

```bash
git clone https://github.com/apple/containerization.git
cd containerization/kernel
make                                            # ~3 min on M-series
container system kernel set --binary ./vmlinux
container system stop && container system start
```

## How it works

```
Agent ──MCP/stdio──▶ sandbox_mcp_server.py (FastMCP)
                           │
                           ├── SandboxManager
                           │     ├── _sandboxes: dict[name, Sandbox]
                           │     ├── _port_forwards: dict[port, PortForward]
                           │     ├── _sync_jobs: dict[id, SyncJob]
                           │     └── _cleanup_loop (idle TTL + child TTL)
                           │
                           ├── SandboxCtlServer (per-parent UDS listener)
                           │     └── NDJSON over /run/sandbox-ctl.sock
                           │           → spawn, list, exec, destroy, run
                           │
                           └── Sandbox (per-VM)
                                 ├── PersistentShell (container exec -i <name> sh)
                                 ├── _bg_processes: dict[id, Process]
                                 └── _audit_log: deque
```

**Latency breakdown:**
- **Cold boot**: ~700ms (Virtualization.framework + EXT4 + network + vminitd)
- **Warm exec**: ~60ms (command piped to persistent shell via vsock)
- **Why warm is fast**: Each sandbox holds open a `container exec -i <name> sh` process. Commands are written to stdin with a unique end-marker, output is read until the marker appears. No process spawn overhead per command.

### Port forwarding

Apple Containers v0.9.0 `-p` port publishing is broken (TCP connects but data never flows), and VM IPs are not routable from the host. Port forwarding works via asyncio TCP proxy:

1. `expose` starts a local TCP server on `127.0.0.1:<host_port>`
2. Each incoming connection spawns `container exec -i <name> nc 127.0.0.1 <container_port>`
3. Data is piped bidirectionally between the client and the nc process via vsock

### Multi-sandbox

Sandboxes are named (default: `"default"`). Each gets isolated volumes for `/workspace` and package caches (apk, pip, npm). Caches persist across resets for fast reinstalls. Sandboxes can reach each other by name via `/etc/hosts` entries auto-injected when networking is available.

### Profiles

Configure per-sandbox-name resources in `SANDBOX_PROFILES` at the top of the server:

```python
SANDBOX_PROFILES = {
    "ml": {"cpus": 4, "memory": "2G"},
    "build": {"cpus": 4, "memory": "1G"},
    "nested": {"cpus": 2, "memory": "1G", "virtualization": True},
}
```

The `virtualization` flag enables nested virtualization (`--virtualization`). GPU/Metal passthrough is not supported by Apple Containers — the kernel has `CONFIG_DRM_VIRTIO_GPU` disabled and the Swift framework doesn't use `VZVirtioGraphicsDeviceConfiguration`.

### Child sandboxes

Sandboxes can spawn child sandboxes, controlled by `SPAWN_POLICIES` at the top of the server. Policies define per-parent limits: max concurrent children, lifetime spawn count, CPU/memory budgets, allowed images, and TTL. Unlisted sandbox names cannot spawn.

Children are lightweight — they skip cache volumes and get their own isolated workspace. They're auto-destroyed when their TTL expires or their parent is reset/destroyed.

### In-container API (`sandbox-ctl`)

When a sandbox has a spawn policy, the server mounts a UDS socket and the `sandbox-ctl` binary into the VM. Code running inside the VM can then spawn/manage sibling containers:

```bash
sandbox-ctl ping                                          # verify connection
sandbox-ctl spawn --image mcp-dev --cpus 1 --memory 256M  # create child
sandbox-ctl list                                           # show children
sandbox-ctl exec <child> -- echo hello                     # run in child
sandbox-ctl destroy <child>                                # tear down
sandbox-ctl run -- echo test                               # ephemeral: spawn + exec + destroy
```

Communication uses NDJSON over the mounted socket (`/run/sandbox-ctl.sock`). The host-side `SandboxCtlServer` handles requests and delegates to `SandboxManager`.

### State persistence

Sandbox-to-container mappings are saved to `~/.local/state/sandbox-mcp/state.json` (schema v2). On restart, the server reconnects to any still-running containers from the previous session. Expired children are cleaned up on reconnect.

## Tools (35)

### Core
| Tool | Description |
|------|-------------|
| `exec` | Run a shell command (~60ms) |
| `python` | Execute Python code |
| `write_file` | Write a file to the sandbox |
| `read_file` | Read a file from the sandbox |
| `batch_write` | Write multiple files in one transfer |
| `install` | Install packages via apk |
| `env` | Manage persistent environment variables |

### Process management
| Tool | Description |
|------|-------------|
| `bg` | Run a command in the background |
| `logs` | Read output from a background process |
| `kill` | Kill a background process |

### Sandbox lifecycle
| Tool | Description |
|------|-------------|
| `status` | Show pool and sandbox info |
| `health` | Quick liveness/disk/memory check across all sandboxes |
| `stats` | Show CPU/memory/disk usage for one sandbox |
| `reset` | Destroy and recreate (clean state) |
| `list_all` | List all active sandboxes |
| `destroy` | Permanently kill a sandbox |
| `clone` | Clone a running sandbox to a new name |
| `history` | Show recent command audit log |

### File transfer
| Tool | Description |
|------|-------------|
| `upload` | Copy files from host into sandbox |
| `download` | Copy files from sandbox to host |
| `git_clone` | Clone a git repo (with optional auth token) |
| `sync_start` | Watch and live-sync a host directory |
| `sync_stop` | Stop a running sync job |

### Snapshots & images
| Tool | Description |
|------|-------------|
| `snapshot` | Save sandbox state as a reusable image |
| `restore` | Boot from a saved snapshot |
| `list_snapshots` | List available snapshots |
| `delete_snapshot` | Delete a saved snapshot image |
| `build_image` | Build a container image from a Containerfile |
| `images` | List all available container images |

### Networking
| Tool | Description |
|------|-------------|
| `expose` | Forward a sandbox port to localhost (TCP proxy) |
| `unexpose` | Stop a port forward |
| `network_info` | Show IPs and connectivity between sandboxes |

### Child sandboxes
| Tool | Description |
|------|-------------|
| `spawn` | Spawn a child sandbox under a parent |
| `children` | List child sandboxes of a parent |
| `destroy_child` | Destroy a child sandbox |

## Files

| File | Description |
|------|-------------|
| `sandbox_mcp_server.py` | Sandbox class, SandboxManager, MCP tool definitions |
| `cmd/sandbox-ctl/` | In-container CLI for spawning sibling sandboxes (Go) |
| `pyproject.toml` | uv/hatchling packaging, entry point `sandbox-mcp` |
| `Containerfile.mcp-dev` | Alpine 3.23 dev image with Python, Node, Go, Rust |
| `tests/` | pytest test suite |

## Customization

Edit constants at the top of `sandbox_mcp_server.py`:

| Constant | Default | Description |
|----------|---------|-------------|
| `DEFAULT_IMAGE` | `"mcp-dev"` | Container image for new sandboxes |
| `SANDBOX_CPUS` | `2` | Default CPU cores per sandbox |
| `SANDBOX_MEMORY` | `"512M"` | Default memory per sandbox |
| `IDLE_TTL` | `1800` | Seconds before auto-destroying idle sandboxes |
| `DEFAULT_TIMEOUT` | `30` | Default command timeout in seconds |
| `MAX_OUTPUT` | `50000` | Max output bytes per command |
| `SPAWN_POLICIES` | `{"default": {...}}` | Per-sandbox child spawn limits and permissions |

## Testing

```bash
uv run pytest tests/ -v
```

## CI

Tests run on Python 3.11, 3.12, and 3.13 via GitHub Actions. Pre-push:

```bash
uv run pytest tests/ -q && python3 -m compileall sandbox_mcp_server.py tests
```
