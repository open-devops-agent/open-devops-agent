"""Docker build log parser — extracts errors from docker build output."""

import re

# GitHub Actions prefixes every log line with a timestamp such as
# "2026-10-23T12:00:00.1234567Z ".
_TIMESTAMP = r"(?:(?P<ts>\d{4}-\d\d-\d\dT[\d:.]+Z) )?"
_CLASSIC_STEP_RE = re.compile(_TIMESTAMP + r"Step \d+(?:/\d+)?[ \t]*:")
_BUILDKIT_STEP_RE = re.compile(_TIMESTAMP + r"#\d+ \[\d+/\d+\]")
_BUILDKIT_ERROR_RE = re.compile(_TIMESTAMP + r"#(?P<id>\d+) ERROR")


def _is_error_line(line: str) -> bool:
    return any(k in line for k in ["ERROR", "error", "failed", "FAILED"])


def _bare(line: str, match: re.Match) -> str:
    """The line without its optional GitHub Actions timestamp prefix."""
    return line[len(match.group("ts")) + 1:] if match.group("ts") else line


def _step_lines(lines: list[str], step_re: re.Pattern) -> list[str]:
    """Step lines matching step_re, each without its timestamp prefix."""
    return [_bare(line, match) for line in lines if (match := step_re.match(line))]


def _failing_step(lines: list[str]) -> str | None:
    """The step that failed: the #N [i/j] step line whose #N ERROR line reports
    the failure, else the last step line before the first error line."""
    error_id = next(
        (match.group("id") for line in lines if (match := _BUILDKIT_ERROR_RE.match(line))),
        None,
    )
    if error_id is not None:
        step = next(
            (
                bare
                for bare in _step_lines(lines, _BUILDKIT_STEP_RE)
                if bare.startswith(f"#{error_id} ")
            ),
            None,
        )
        if step is not None:
            return step
    first_error = next((i for i, line in enumerate(lines) if _is_error_line(line)), None)
    if first_error is None:
        return None
    for step_re in (_CLASSIC_STEP_RE, _BUILDKIT_STEP_RE):
        steps = _step_lines(lines[:first_error], step_re)
        if steps:
            return steps[-1]
    return None


def _first_step(lines: list[str]) -> str | None:
    for step_re in (_CLASSIC_STEP_RE, _BUILDKIT_STEP_RE):
        steps = _step_lines(lines, step_re)
        if steps:
            return steps[0]
    return None


def parse_build_error(log: str) -> dict:
    lines = log.splitlines()
    error_lines = [l for l in lines if _is_error_line(l)]
    step = _failing_step(lines) or _first_step(lines)
    if step is None:
        step = next((l for l in lines if "failed to solve:" in l), "Unknown step")
    return {"step": step, "errors": error_lines[:20], "raw": log[-3000:]}
