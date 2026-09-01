"""Helpers for executing external scanner binaries safely."""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass

logger = logging.getLogger("prcampus.scanner.process")


@dataclass
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


def which(binary: str) -> str | None:
    """Resolve a scanner binary on PATH (or accept an absolute path)."""
    return shutil.which(binary)


def run_command(args: list[str], timeout: int, input_text: str | None = None) -> CommandResult:
    """Run an external tool.

    The argument list is always passed as a sequence (never a shell string), so
    target values cannot be used for command injection.
    """
    logger.debug("Executing: %s", " ".join(args))
    try:
        completed = subprocess.run(  # noqa: S603 - argument list, shell=False
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            check=False,
            shell=False,
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            exit_code=124,
            stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=f"The scanner exceeded its {timeout}s timeout and was terminated.",
            timed_out=True,
        )
    except FileNotFoundError:
        return CommandResult(127, "", f"Executable not found: {args[0]}")
    except Exception as exc:  # pragma: no cover
        return CommandResult(1, "", f"{type(exc).__name__}: {exc}")


def tool_version(binary: str, flag: str = "--version", timeout: int = 10) -> str | None:
    path = which(binary)
    if not path:
        return None
    result = run_command([path, flag], timeout=timeout)
    output = (result.stdout or result.stderr).strip()
    return output.splitlines()[0][:80] if output else None
