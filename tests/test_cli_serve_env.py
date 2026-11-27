"""Regression tests for issue #41: `devops-agent serve` must honour
HOST/PORT/UVICORN_WORKERS from .env.

`cmd_serve` in `devops_agent/cli.py` reads the three variables with
`os.getenv`, but the only `load_dotenv()` on the serve path lived in
`api/server.py` — a module uvicorn imports from the string `"api.server:app"`
*after* the reads. Values in `.env` therefore never reached the server.

These tests drive the real `devops_agent.cli.main()` with real argv; only
`uvicorn.run` is stubbed. The `.env` is written to the repo root because
`cmd_serve` loads `Path.cwd() / ".env"` explicitly and pytest runs with the
repo root as cwd — the same layout a source-checkout run of the CLI sees.
`test_serve_reads_dotenv_from_invocation_cwd` covers the installed layout,
where the module lives outside the directory containing `.env`.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from devops_agent import cli

REPO_ROOT = Path(cli.__file__).resolve().parent.parent
SERVE_ENV_VARS = ("HOST", "PORT", "UVICORN_WORKERS", "WEB_CONCURRENCY")


@pytest.fixture(autouse=True)
def shared_storage(monkeypatch):
    """These tests are about where settings come from; several workers need shared
    storage (#224), so declare one. The memory guard has its own tests."""
    monkeypatch.setenv("STORAGE_PROVIDER", "s3")


@pytest.fixture
def dotenv_file(monkeypatch):
    """Provide a repo-root .env with the three serve settings, and guarantee
    none of them leaks in from the ambient shell environment.

    A pre-existing repo-root .env (CI's dummy-env step creates one before
    pytest) is tolerated: its exact bytes are restored after the test. When
    none existed, the file is removed again, so the absent-file case keeps
    its original isolation.
    """
    for name in SERVE_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    env_path = REPO_ROOT / ".env"
    original_bytes = env_path.read_bytes() if env_path.exists() else None
    env_path.write_text("HOST=203.0.113.7\nPORT=7777\nUVICORN_WORKERS=9\n")
    try:
        yield env_path
    finally:
        if original_bytes is None:
            env_path.unlink()
        else:
            env_path.write_bytes(original_bytes)


def _run_serve(*argv: str) -> dict:
    """Run `devops-agent serve <argv>` with uvicorn stubbed; return run()'s kwargs."""
    with patch.object(sys, "argv", ["devops-agent", "serve", *argv]), patch(
        "uvicorn.run"
    ) as run:
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
    assert exc_info.value.code == 0
    run.assert_called_once()
    return run.call_args.kwargs


def test_serve_honours_dotenv(dotenv_file):
    kwargs = _run_serve()
    assert kwargs["host"] == "203.0.113.7"
    assert kwargs["port"] == 7777
    assert kwargs["workers"] == 9


def test_shell_environment_overrides_dotenv(dotenv_file, monkeypatch):
    """An already-exported variable beats .env (load_dotenv default: no override)."""
    monkeypatch.setenv("PORT", "5555")
    assert _run_serve()["port"] == 5555


def test_cli_flags_override_dotenv(dotenv_file):
    kwargs = _run_serve("--host", "192.0.2.1", "--port", "9090", "--workers", "4")
    assert kwargs["host"] == "192.0.2.1"
    assert kwargs["port"] == 9090
    assert kwargs["workers"] == 4


def test_serve_defaults_unchanged_without_dotenv(monkeypatch):
    for name in SERVE_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    kwargs = _run_serve()
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 8000
    assert kwargs["workers"] == 1  # one worker by default (#224)


def test_serve_reads_dotenv_from_invocation_cwd(tmp_path, monkeypatch):
    """The installed CLI must read `.env` from the directory the user runs it in.

    Simulates the package living outside the directory containing `.env`:
    the module stays where it is installed (here: this clone, which pytest
    imported), while the process cwd is an unrelated invocation directory
    holding the only `.env`. A bare `load_dotenv()` anchors its upward
    search at the calling module, so this `.env` is silently ignored after
    a normal installation and uvicorn starts on its defaults.
    """
    for name in SERVE_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    (tmp_path / ".env").write_text("HOST=203.0.113.7\nPORT=7777\nUVICORN_WORKERS=9\n")
    monkeypatch.chdir(tmp_path)
    kwargs = _run_serve()
    assert kwargs["host"] == "203.0.113.7"
    assert kwargs["port"] == 7777
    assert kwargs["workers"] == 9
