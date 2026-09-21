"""
Guards that every environment variable the code reads is listed in `.env.example`.

`.env.example` is the only place an operator can discover what the agent is
configurable by. A variable added with `os.getenv(...)` and never written down
becomes a deployment surprise — the default silently wins in production.

Detection is AST-based rather than regex-based: a comment mentioning
`os.getenv("FOO")` is discarded by the tokenizer and never reaches the tree, and
a string that merely spells out an env lookup parses to `ast.Constant`, not to a
`Call`, so neither can produce a false failure. Only `os.getenv` /
`os.environ.get` / `os.environ[...]` / `os.environ.setdefault` /
`os.environ.pop` with a string-literal name are collected.
"""

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = REPO_ROOT / ".env.example"

# Directories with no application code (virtualenvs, build output, VCS metadata).
SKIPPED_DIRS = {
    ".git",
    ".venv",
    ".test-venv",
    "venv",
    "env",
    ".tox",
    ".pytest_cache",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    "__pycache__",
}

# Variables read from code but deliberately absent from `.env.example`, each with
# the reason it stays out. An entry here is a promise that operators must never
# set the variable, so keep the list short and keep the reasons current.
#
# `tests/test_ci_env_alignment.py::CI_ONLY_KEYS` carries the same rationale for
# the other direction (names CI assigns). The two lists are intentionally
# separate: they answer different questions and may legitimately diverge.
UNDOCUMENTED_BY_DESIGN = {
    # Test-harness flag. `.github/workflows/ci.yml` sets `TESTING: true` for the
    # unit-test job and the integration API server so suites can skip work that
    # needs live credentials. It is not an application setting, and documenting
    # it in `.env.example` would invite operators to enable it in production.
    "TESTING": "CI-only test-harness flag, never a production setting",
}

# A name counts as documented when `.env.example` carries a `NAME=` line for it.
# The optional leading `#` accepts commented-out example blocks (the MinIO and
# Azure storage sections are written that way on purpose), which document a
# variable just as well as a live assignment. Requiring the `=` keeps an
# incidental prose mention from passing as documentation.
ENV_EXAMPLE_ENTRY_RE = re.compile(r"^[ \t]*#?[ \t]*([A-Z][A-Z0-9_]*)=", re.MULTILINE)

# Attribute bases that name the process environment.
_ENVIRON_BASES = {"os.environ", "environ"}
_OS_BASES = {"os"}
# `os.environ.<method>(...)` calls whose first argument is a variable name.
_ENVIRON_METHODS = {"get", "setdefault", "pop"}


class _EnvVarCollector(ast.NodeVisitor):
    """Collects string-literal environment variable names read by a module."""

    def __init__(self, relative_path):
        self.relative_path = relative_path
        self.names = {}

    def _record(self, name, node):
        self.names.setdefault(name, f"{self.relative_path}:{node.lineno}")

    def _record_first_arg(self, node):
        if not node.args:
            return
        first = node.args[0]
        # Dynamic names (`os.getenv(key)` over ORG_CREDENTIAL_KEYS) cannot be
        # resolved statically; `tests/test_ci_env_alignment.py` guards those.
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            self._record(first.value, node)

    def visit_Call(self, node):
        func = node.func
        if isinstance(func, ast.Attribute):
            base = ast.unparse(func.value)
            if (func.attr == "getenv" and base in _OS_BASES) or (
                func.attr in _ENVIRON_METHODS and base in _ENVIRON_BASES
            ):
                self._record_first_arg(node)
        self.generic_visit(node)

    def visit_Subscript(self, node):
        if ast.unparse(node.value) in _ENVIRON_BASES:
            key = node.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                self._record(key.value, node)
        self.generic_visit(node)


def _python_sources():
    for path in sorted(REPO_ROOT.rglob("*.py")):
        if SKIPPED_DIRS.isdisjoint(path.relative_to(REPO_ROOT).parts):
            yield path


def _referenced_env_vars():
    """Map every env var read anywhere in the tree to one `path:line` citation."""
    references = {}
    for path in _python_sources():
        relative_path = path.relative_to(REPO_ROOT).as_posix()
        collector = _EnvVarCollector(relative_path)
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        collector.visit(ast.parse(source, filename=relative_path))
        for name, location in collector.names.items():
            references.setdefault(name, location)
    return references


def _documented_env_vars():
    return set(ENV_EXAMPLE_ENTRY_RE.findall(ENV_EXAMPLE.read_text(encoding="utf-8")))


def test_every_env_var_read_by_code_is_in_env_example():
    references = _referenced_env_vars()

    # Guard the scanner itself: a broken scrape would pass vacuously.
    assert references, "no os.getenv/os.environ references found anywhere in the tree"
    assert "ANTHROPIC_API_KEY" in references, (
        "scanner missed a known env var read (ANTHROPIC_API_KEY) — its detection "
        "of os.getenv/os.environ has regressed"
    )

    documented = _documented_env_vars()
    undocumented = sorted(set(references) - documented - set(UNDOCUMENTED_BY_DESIGN))
    detail = "\n".join(
        f"  {name}  (read at {references[name]})" for name in undocumented
    )
    assert undocumented == [], (
        "these environment variables are read by the code but have no `NAME=` "
        "line in .env.example — document them there, or add them to "
        f"UNDOCUMENTED_BY_DESIGN with a reason:\n{detail}"
    )


def test_undocumented_by_design_entries_are_still_undocumented():
    """Keeps the allow-list from rotting once a variable gets documented."""
    documented = _documented_env_vars()
    stale = sorted(set(UNDOCUMENTED_BY_DESIGN) & documented)
    assert stale == [], (
        "these UNDOCUMENTED_BY_DESIGN entries are now declared in .env.example; "
        "drop them from the allow-list: " + str(stale)
    )


def test_scanner_skips_unreadable_python_files(tmp_path, monkeypatch):
    """A non-UTF-8 Python file outside the application tree is ignored."""
    (tmp_path / "app.py").write_text(
        'import os\nos.getenv("KNOWN_ENV")\n', encoding="utf-8"
    )
    (tmp_path / "broken.py").write_bytes(b"\xff\xfe\xfd")
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)

    assert _referenced_env_vars() == {"KNOWN_ENV": "app.py:2"}
