"""Execution of external scanner binaries.

Scanners run as child processes with a scrubbed environment (so credentials in the
operator's shell or CI job never reach them), no shell, a timeout, an output size cap
and a kill switch that is honoured while they run.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from htw.core.scope import KillSwitch
from htw.errors import KillSwitchEngaged, ToolError

# Variables a scanner needs to start, find its caches and reach a vulnerability
# database through a corporate proxy. Everything else is dropped.
BASE_ENV_ALLOWLIST = (
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "TMPDIR", "TEMP", "TMP", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "SYSTEMROOT", "APPDATA", "LOCALAPPDATA", "USERPROFILE",
)  # fmt: skip

POLL_SECONDS = 0.2
STDERR_TAIL_CHARS = 2000


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float

    @property
    def stderr_tail(self) -> str:
        return self.stderr[-STDERR_TAIL_CHARS:].strip()


class ToolRunner:
    def __init__(
        self,
        timeout_seconds: int = 900,
        max_output_bytes: int = 256 * 1024 * 1024,
        env_passthrough: Sequence[str] = (),
        kill_switch: KillSwitch | None = None,
        environ: Mapping[str, str] | None = None,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self._kill_switch = kill_switch
        source = os.environ if environ is None else environ
        allowed = (*BASE_ENV_ALLOWLIST, *env_passthrough)
        self._env = {name: source[name] for name in allowed if name in source}

    @property
    def env(self) -> dict[str, str]:
        return dict(self._env)

    def which(self, binary: str) -> str | None:
        return shutil.which(binary, path=self._env.get("PATH"))

    def run(
        self,
        argv: Sequence[str],
        cwd: Path,
        timeout_seconds: int | None = None,
        extra_env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        """Run `argv` to completion and return its output.

        A non-zero exit status is returned, not raised: several scanners use it to
        signal "findings present". Timeouts, oversized output and the kill switch raise.
        """
        if self._kill_switch is not None:
            self._kill_switch.raise_if_engaged()
        timeout = timeout_seconds or self.timeout_seconds
        env = {**self._env, **(extra_env or {})}
        name = Path(argv[0]).name
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="htw-run-") as scratch:
            out_path = Path(scratch) / "stdout"
            err_path = Path(scratch) / "stderr"
            with open(out_path, "wb") as out, open(err_path, "wb") as err:
                try:
                    process = subprocess.Popen(
                        list(argv),
                        cwd=str(cwd),
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=out,
                        stderr=err,
                        start_new_session=True,
                    )
                except OSError as exc:
                    raise ToolError(f"{name}: could not be started: {exc}") from None
                failure = self._wait(process, name, started, timeout, out_path, err_path)
            if failure is not None:
                raise failure
            return CommandResult(
                argv=tuple(argv),
                returncode=process.returncode,
                stdout=out_path.read_text(encoding="utf-8", errors="replace"),
                stderr=err_path.read_text(encoding="utf-8", errors="replace"),
                duration_seconds=round(time.monotonic() - started, 3),
            )

    def _wait(
        self,
        process: subprocess.Popen[bytes],
        name: str,
        started: float,
        timeout: int,
        out_path: Path,
        err_path: Path,
    ) -> Exception | None:
        while True:
            try:
                process.wait(timeout=POLL_SECONDS)
                return None
            except subprocess.TimeoutExpired:
                pass
            if time.monotonic() - started > timeout:
                _terminate(process)
                return ToolError(f"{name}: timed out after {timeout}s and was stopped")
            if out_path.stat().st_size + err_path.stat().st_size > self.max_output_bytes:
                _terminate(process)
                return ToolError(
                    f"{name}: output exceeded {self.max_output_bytes // (1024 * 1024)} MiB "
                    "and was stopped"
                )
            reason = self._kill_switch.reason() if self._kill_switch else None
            if reason:
                _terminate(process)
                return KillSwitchEngaged(f"kill switch engaged ({reason}); {name} was stopped")


def _terminate(process: subprocess.Popen[bytes]) -> None:
    """Stop the scanner and anything it spawned."""
    for sig, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
        try:
            os.killpg(process.pid, sig)
        except (ProcessLookupError, PermissionError, AttributeError):
            process.kill()
        try:
            process.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue
