"""A second process on private in-memory storage refuses to start instead of losing incidents (#224)."""
import asyncio
import re
from pathlib import Path

import pytest

from api import server
from storage.memory_storage import MemoryStorage

ROOT = Path(__file__).resolve().parents[1]


def run_lifespan(monkeypatch, lock_handle, storage):
    monkeypatch.setattr(server, "acquire_background_worker_lock", lambda: lock_handle)
    monkeypatch.setattr(server, "release_background_worker_lock", lambda handle: None)
    monkeypatch.setattr(server.incident_queue, "adopt_legacy_reviews", lambda: None)
    monkeypatch.setattr(server.incident_store, "storage", storage)
    monkeypatch.setattr(server, "_queue_worker_loop", lambda: asyncio.sleep(0))
    monkeypatch.setattr(server, "_retention_loop", lambda: asyncio.sleep(0))
    monkeypatch.setattr(server, "_containment_loop", lambda: asyncio.sleep(0))

    async def run():
        async with server.lifespan(server.app):
            pass

    asyncio.run(run())


def test_second_process_on_memory_storage_refuses_to_start(monkeypatch):
    with pytest.raises(RuntimeError, match="in-memory storage"):
        run_lifespan(monkeypatch, None, MemoryStorage())


def test_first_process_on_memory_storage_starts(monkeypatch):
    run_lifespan(monkeypatch, object(), MemoryStorage())


def test_second_process_on_shared_storage_starts(monkeypatch):
    shared = object()  # any non-memory provider (S3, GCS, Azure, MinIO) is visible to every process
    run_lifespan(monkeypatch, None, shared)


def test_docker_image_defaults_to_one_worker():
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text()
    assert "ENV WEB_CONCURRENCY=1" in dockerfile
    cmd = [line for line in dockerfile.splitlines() if line.startswith("CMD")][-1]
    assert "${WEB_CONCURRENCY:-1}" in cmd and not re.search(r"--workers\", \"[2-9]", cmd)


def test_cli_defaults_to_one_worker_and_refuses_more_on_memory(monkeypatch, capsys):
    import argparse

    from devops_agent import cli

    import sys
    import types

    calls = []
    monkeypatch.setitem(sys.modules, "uvicorn", types.SimpleNamespace(run=lambda *a, **k: calls.append(k)))
    monkeypatch.setattr(cli, "load_dotenv", lambda *a, **k: None)
    for var in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "STORAGE_PROVIDER", "HOST", "PORT"):
        monkeypatch.delenv(var, raising=False)

    def args(workers=None):
        return argparse.Namespace(host=None, port=None, workers=workers, reload=False)

    assert cli.cmd_serve(args()) == 0 and calls[-1]["workers"] == 1

    assert cli.cmd_serve(args(3)) == 2
    assert "needs shared storage" in capsys.readouterr().err

    monkeypatch.setenv("STORAGE_PROVIDER", "s3")
    assert cli.cmd_serve(args(3)) == 0 and calls[-1]["workers"] == 3

    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    assert cli.cmd_serve(args()) == 0 and calls[-1]["workers"] == 4
