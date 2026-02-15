from __future__ import annotations

import asyncio
import json

import pytest

from tests.conftest import _configure_module, _manager


def test_manager_boot_status_and_reset(
    mock_container_cli, monkeypatch: pytest.MonkeyPatch
):
    import sandbox_mcp_server as sm

    _configure_module(sm, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(sm) as mgr:
            sb = await mgr.get_sandbox("ci")
            assert sb.name.startswith("mcp-sb-")

            status = await mgr.status()
            assert "ci" in status["sandboxes"]
            assert status["sandboxes"]["ci"]["shell"] == "alive"

            reset_msg = await mgr.reset(name="ci", wipe_workspace=False)
            assert "Fresh sandbox 'ci' ready" in reset_msg

    asyncio.run(scenario())


def test_tools_exec_file_stats_roundtrip(
    mock_container_cli, monkeypatch: pytest.MonkeyPatch
):
    import sandbox_mcp_server as sm

    _configure_module(sm, monkeypatch, mock_container_cli)
    workspace = mock_container_cli["workspace_dir"]

    async def scenario():
        async with _manager(sm) as mgr:
            monkeypatch.setattr(sm, "manager", mgr)
            target = workspace / "note.txt"

            write_msg = await sm.write_file(
                path=str(target),
                content="hello",
                sandbox="dev",
            )
            assert "Wrote 5 bytes" in write_msg

            read_content = await sm.read_file(path=str(target), sandbox="dev")
            assert read_content == "hello"

            exec_out = await sm.exec(
                command="wc -c",
                stdin="abcdef",
                workdir=str(workspace),
                sandbox="dev",
            )
            assert "6" in exec_out

            stats = await sm.stats(sandbox="dev")
            assert "Memory:" in stats
            assert "History:" in stats

    asyncio.run(scenario())


def test_tool_env_set_list_unset(mock_container_cli, monkeypatch: pytest.MonkeyPatch):
    import sandbox_mcp_server as sm

    _configure_module(sm, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(sm) as mgr:
            monkeypatch.setattr(sm, "manager", mgr)
            set_msg = await sm.env(
                action="set",
                key="API_KEY",
                value="it's secret",
                sandbox="cfg",
            )
            assert "Set API_KEY" in set_msg

            listed = await sm.env(action="list", sandbox="cfg")
            assert "export API_KEY='it'\\''s secret'" in listed

            unset_msg = await sm.env(action="unset", key="API_KEY", sandbox="cfg")
            assert "Unset API_KEY" in unset_msg

            listed_after = await sm.env(action="list", sandbox="cfg")
            assert listed_after.startswith("No persistent env vars set")

    asyncio.run(scenario())


def test_history_bg_and_lifecycle_views(
    mock_container_cli, monkeypatch: pytest.MonkeyPatch
):
    import sandbox_mcp_server as sm

    _configure_module(sm, monkeypatch, mock_container_cli)
    workspace = mock_container_cli["workspace_dir"]

    async def scenario():
        async with _manager(sm) as mgr:
            monkeypatch.setattr(sm, "manager", mgr)
            secret = "SUPER_SECRET_TOKEN_123"
            out = await sm.exec(
                command=f"echo {secret}",
                workdir=str(workspace),
                sandbox="hist",
            )
            assert secret in out

            history = await sm.history(limit=10, sandbox="hist")
            assert "echo" in history

            bg_msg = await sm.bg(
                command="sleep 1",
                name="bg-secret",
                workdir=str(workspace),
                sandbox="hist",
            )
            assert "Started [bg-secret]" in bg_msg

            bg_logs = await sm.logs(name="bg-secret", sandbox="hist")
            assert "bg-secret" in bg_logs

            status = await sm.status()
            assert "hist" in status

            listing = await sm.list_all()
            assert "hist" in listing

            destroy_msg = await sm.destroy(sandbox="hist")
            assert "Destroyed sandbox 'hist'" in destroy_msg

    asyncio.run(scenario())


def test_upload_download_batch_and_sync(
    mock_container_cli, monkeypatch: pytest.MonkeyPatch
):
    import sandbox_mcp_server as sm

    _configure_module(sm, monkeypatch, mock_container_cli)
    workspace = mock_container_cli["workspace_dir"]

    async def scenario():
        async with _manager(sm) as mgr:
            monkeypatch.setattr(sm, "manager", mgr)
            local_src = workspace / "local-src.txt"
            local_src.write_text("upload-content")

            upload_msg = await sm.upload(
                local_path=str(local_src),
                sandbox_path=str(workspace / "remote"),
                sandbox="io",
            )
            assert "Uploaded" in upload_msg

            local_dst = workspace / "downloaded-dir"
            download_msg = await sm.download(
                sandbox_path=str(workspace / "remote"),
                local_path=str(local_dst),
                sandbox="io",
            )
            assert "Downloaded" in download_msg
            assert (local_dst / "local-src.txt").read_text() == "upload-content"

            sync_src = workspace / "sync-src"
            sync_src.mkdir()
            (sync_src / "one.txt").write_text("1")

            sync_msg = await sm.sync_start(
                local_dir=str(sync_src),
                sandbox_dir=str(workspace / "sync-dst"),
                sandbox="io",
            )
            assert "Sync started" in sync_msg
            job_id = sync_msg.split("[", 1)[1].split("]", 1)[0]
            stop_msg = await sm.sync_stop(job_id)
            assert f"Stopped sync [{job_id}]" in stop_msg

    asyncio.run(scenario())


def test_batch_write_tool_validation_and_dispatch(
    mock_container_cli, monkeypatch: pytest.MonkeyPatch
):
    import sandbox_mcp_server as sm

    _configure_module(sm, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(sm) as mgr:
            monkeypatch.setattr(sm, "manager", mgr)

            captured: dict[str, object] = {}

            async def fake_write_files(sandbox_name: str, files: dict[str, str]) -> str:
                captured["sandbox"] = sandbox_name
                captured["files"] = files
                return f"Wrote {len(files)} files"

            monkeypatch.setattr(mgr, "write_files", fake_write_files)
            bad_json = await sm.batch_write(files="{not-json", sandbox="bw")
            assert "invalid JSON" in bad_json

            not_obj = await sm.batch_write(files='["a"]', sandbox="bw")
            assert "must be a JSON object" in not_obj

            payload = {
                "/workspace/a.txt": "A",
                "/workspace/b.txt": "B",
            }
            ok = await sm.batch_write(files=json.dumps(payload), sandbox="bw")
            assert "Wrote 2 files" in ok
            assert captured["sandbox"] == "bw"
            assert captured["files"] == payload

    asyncio.run(scenario())


def test_build_and_list_images_and_snapshot_error_paths(
    mock_container_cli, monkeypatch: pytest.MonkeyPatch
):
    import sandbox_mcp_server as sm

    _configure_module(sm, monkeypatch, mock_container_cli)

    async def scenario():
        async with _manager(sm) as mgr:
            monkeypatch.setattr(sm, "manager", mgr)
            build_msg = await sm.build_image(
                name="custom-image",
                containerfile="FROM mcp-dev\nRUN echo ok\n",
            )
            assert "Built image 'custom-image'" in build_msg

            images = await sm.images()
            assert "mcp-dev" in images
            assert "custom-image" in images

            snaps = await sm.list_snapshots()
            assert "No snapshots saved" in snaps

            restore_err = await sm.restore(snapshot_name="missing", sandbox="img")
            assert "not found" in restore_err

            delete_err = await sm.delete_snapshot(snapshot_name="missing")
            assert "not found" in delete_err

    asyncio.run(scenario())
