# sandbox-mcp

[![CI](https://github.com/bird/sandbox-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/bird/sandbox-mcp/actions/workflows/ci.yml)

Local AI agent sandbox. Run isolated Linux VMs on your Mac in ~60ms. Zero cloud costs, hardware-level isolation, works with any MCP client (Claude Code, Claude Desktop, Cursor).

## What this is

An MCP server that gives AI agents a sandboxed Linux environment using [Apple Containerization](https://github.com/apple/containerization) (Virtualization.framework). Each sandbox is a real VM — not a container sharing your kernel — that boots in ~700ms and executes commands in ~60ms via a persistent shell over vsock.

**Compared to cloud sandboxes:**

| | Exec latency | Cost | Isolation |
|---|---|---|---|
| **This (local)** | ~60ms | Free | VM (Virtualization.framework) |
| E2B | ~150ms + network | $0.18/hr | Firecracker microVM |
| Daytona | ~90ms + network | Usage-based | Docker container |

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
                           │     └── _cleanup_loop (idle TTL auto-destroy)
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

1. `sandbox_expose` starts a local TCP server on `127.0.0.1:<host_port>`
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

### State persistence

Sandbox-to-container mappings are saved to `~/.local/state/sandbox-mcp/state.json`. On restart, the server reconnects to any still-running containers from the previous session.

## Tools (32)

### Core
| Tool | Description |
|------|-------------|
| `sandbox_exec` | Run a shell command (~60ms) |
| `sandbox_python` | Execute Python code |
| `sandbox_write_file` | Write a file to the sandbox |
| `sandbox_read_file` | Read a file from the sandbox |
| `sandbox_batch_write` | Write multiple files in one transfer |
| `sandbox_install` | Install packages via apk |
| `sandbox_env` | Manage persistent environment variables |

### Process management
| Tool | Description |
|------|-------------|
| `sandbox_bg` | Run a command in the background |
| `sandbox_logs` | Read output from a background process |
| `sandbox_kill` | Kill a background process |

### Sandbox lifecycle
| Tool | Description |
|------|-------------|
| `sandbox_status` | Show pool and sandbox info |
| `sandbox_health` | Quick liveness/disk/memory check across all sandboxes |
| `sandbox_stats` | Show CPU/memory/disk usage for one sandbox |
| `sandbox_reset` | Destroy and recreate (clean state) |
| `sandbox_list` | List all active sandboxes |
| `sandbox_destroy` | Permanently kill a sandbox |
| `sandbox_clone` | Clone a running sandbox to a new name |
| `sandbox_history` | Show recent command audit log |

### File transfer
| Tool | Description |
|------|-------------|
| `sandbox_upload` | Copy files from host into sandbox |
| `sandbox_download` | Copy files from sandbox to host |
| `sandbox_git_clone` | Clone a git repo (with optional auth token) |
| `sandbox_sync_start` | Watch and live-sync a host directory |
| `sandbox_sync_stop` | Stop a running sync job |

### Snapshots & images
| Tool | Description |
|------|-------------|
| `sandbox_snapshot` | Save sandbox state as a reusable image |
| `sandbox_restore` | Boot from a saved snapshot |
| `sandbox_list_snapshots` | List available snapshots |
| `sandbox_delete_snapshot` | Delete a saved snapshot image |
| `sandbox_build_image` | Build a container image from a Containerfile |
| `sandbox_images` | List all available container images |

### Networking
| Tool | Description |
|------|-------------|
| `sandbox_expose` | Forward a sandbox port to localhost (TCP proxy) |
| `sandbox_unexpose` | Stop a port forward |
| `sandbox_network_info` | Show IPs and connectivity between sandboxes |

## Files

| File | Description |
|------|-------------|
| `sandbox_mcp_server.py` | Everything: Sandbox class, SandboxManager, 32 MCP tools |
| `pyproject.toml` | uv/hatchling packaging, entry point `sandbox-mcp` |
| `Containerfile.mcp-dev` | Alpine 3.23 with Python, Node, Go, Rust |
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

## Testing

```bash
uv run pytest tests/ -v
```

## CI Expectations

CI is configured in `.github/workflows/ci.yml` and enforces:

- Python test matrix: 3.11 and 3.12
- `pytest` must pass (`tests/`)
- `compileall` must pass for `sandbox_mcp_server.py` and `tests/`
- Package build must succeed (`python -m build`)

Recommended local pre-push check:

```bash
uv run pytest tests/ -q && python3 -m compileall sandbox_mcp_server.py tests
```
