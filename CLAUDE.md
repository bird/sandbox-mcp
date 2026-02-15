# sandbox-mcp

MCP server for Apple Container sandboxes. Single-file Python server (`sandbox_mcp_server.py`) using FastMCP.

## Project structure

```
sandbox_mcp_server.py   # Sandbox class, SandboxManager, MCP tools
cmd/sandbox-ctl/       # In-container CLI for spawning sibling containers (Go)
pyproject.toml          # uv/hatchling packaging, entry point: sandbox-mcp
Containerfile.mcp-dev   # Alpine 3.23 image with Python/Node/Go/Rust
tests/                  # pytest test suite
```

## Key patterns

- **Shell quoting**: Always use `_sq(value)` for any user-provided string interpolated into shell commands. Never use f-string quotes.
- **Env key validation**: Use `_validate_env_key(key)` before any env var operations.
- **Audit logging**: Pass `audit=False` for internal/diagnostic commands to keep the audit log clean.
- **Port forwarding**: Uses `container exec -i <name> nc` proxy, NOT `-p` flag (broken in Apple Containers v0.9.0).
- **Profile tuple**: `_get_profile()` returns `(cpus, memory, virtualization)` — 3-tuple, unpack accordingly.

## Running

```bash
uv run sandbox-mcp              # stdio mode (for MCP clients)
python3 sandbox_mcp_server.py   # also works
```

## Testing

```bash
uv run pytest tests/ -v
```

## Adding a new tool

1. Add manager method to `SandboxManager` class
2. Add `@mcp_server.tool()` function that calls the manager method
3. Run tests
