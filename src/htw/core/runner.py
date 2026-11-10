"""Execution of external scanner binaries.

Scanners run as child processes with a scrubbed environment (so credentials in the
operator's shell or CI job never reach them), no shell, a timeout, an output size cap
and a kill switch that is honoured while they run.

When `bwrap` is usable, scanner processes are wrapped so they can read the asset and
nothing else the operator did not already name (a cache directory in
`env_passthrough`, or the report directory). The asset is read-only. The operator's
home directory is not mounted. Tools whose network note is "none" also lose the
network. `git` and `gh`, which publish a draft pull request, are not wrapped: they
need the login the operator already has.
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

# Read-only mounts a dynamic binary needs. Never the operator's home.
_SYSTEM_DIRS = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/opt", "/nix")

POLL_SECONDS = 0.2
STDERR_TAIL_CHARS = 2000


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    sandboxed: bool = False

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
        sandbox: str = "auto",
    ):
        if sandbox not in ("auto", "off"):
            raise ToolError(f"runner sandbox must be 'auto' or 'off' (got {sandbox!r})")
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.sandbox = sandbox
        self._kill_switch = kill_switch
        self._passthrough = tuple(env_passthrough)
        source = os.environ if environ is None else environ
        allowed = (*BASE_ENV_ALLOWLIST, *env_passthrough)
        self._env = {name: source[name] for name in allowed if name in source}
        self._sandbox_ready: bool | None = None
        self.sandbox_note: str | None = None
        self.last_sandboxed = False

    @property
    def env(self) -> dict[str, str]:
        return dict(self._env)

    def which(self, binary: str) -> str | None:
        return shutil.which(binary, path=self._env.get("PATH"))

    def ensure_sandbox(self) -> None:
        """Decide once whether bubblewrap can wrap a process."""
        if self._sandbox_ready is not None:
            return
        if self.sandbox == "off":
            self._sandbox_ready = False
            return
        bwrap = self.which("bwrap")
        if bwrap is None:
            self._sandbox_ready = False
            self.sandbox_note = "bwrap is not installed, so scanner processes are not sandboxed"
            return
        try:
            probe = subprocess.run(
                [bwrap, "--unshare-user", "--die-with-parent", "--ro-bind", "/", "/", "--", "true"],
                check=False,
                capture_output=True,
                timeout=10,
                env=self._env,
            )
        except (OSError, subprocess.TimeoutExpired):
            probe = None
        if probe is None or probe.returncode != 0:
            self._sandbox_ready = False
            self.sandbox_note = (
                "bwrap cannot start a sandbox here, so scanner processes are not sandboxed"
            )
            return
        self._sandbox_ready = True

    def sandbox_status(self) -> str:
        self.ensure_sandbox()
        if self.sandbox == "off":
            return "Process sandbox: off in the scope file. Scanners run as this user."
        if self.sandbox_note:
            return f"Process sandbox: {self.sandbox_note}."
        return (
            "Process sandbox: bubblewrap wraps scanner processes "
            "(read-only asset, private home, no extra paths)."
        )

    def run(
        self,
        argv: Sequence[str],
        cwd: Path,
        timeout_seconds: int | None = None,
        extra_env: Mapping[str, str] | None = None,
        *,
        sandbox: bool | None = None,
        offline: bool = False,
        writable: Sequence[Path] = (),
        read_root: Path | None = None,
    ) -> CommandResult:
        """Run `argv` to completion and return its output.

        A non-zero exit status is returned, not raised: several scanners use it to
        signal "findings present". Timeouts, oversized output and the kill switch raise.

        `sandbox=False` is for `git` and `gh`, which need the operator's existing
        login. Scanners leave it on. The asset is never made writable, and the home
        directory is never mounted.
        """
        if self._kill_switch is not None:
            self._kill_switch.raise_if_engaged()
        if sandbox is not False:
            self.ensure_sandbox()
        enabled = False if sandbox is False else bool(self._sandbox_ready)
        timeout = timeout_seconds or self.timeout_seconds
        env = {**self._env, **(extra_env or {})}
        name = Path(argv[0]).name
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="htw-run-") as scratch:
            scratch_path = Path(scratch)
            command, run_env = self._command(
                list(argv), cwd, read_root or cwd, offline, writable, env, scratch_path, enabled
            )
            result = self._spawn(command, cwd, run_env, name, started, timeout, scratch_path)
            if (
                enabled
                and result.returncode != 0
                and not result.stdout.strip()
                and result.stderr.lstrip().startswith("bwrap:")
            ):
                self._sandbox_ready = False
                self.sandbox_note = (
                    "bwrap failed to start a scanner, so scanner processes are not sandboxed"
                )
                command, run_env = list(argv), env
                result = self._spawn(command, cwd, run_env, name, started, timeout, scratch_path)
                result = CommandResult(
                    result.argv, result.returncode, result.stdout, result.stderr,
                    result.duration_seconds, False,
                )  # fmt: skip
            self.last_sandboxed = result.sandboxed
            return result

    def _command(
        self,
        argv: list[str],
        cwd: Path,
        read_root: Path,
        offline: bool,
        writable: Sequence[Path],
        env: dict[str, str],
        scratch: Path,
        enabled: bool,
    ) -> tuple[list[str], dict[str, str]]:
        if not enabled:
            return argv, env
        bwrap = self.which("bwrap")
        if bwrap is None:
            return argv, env
        cwd = cwd.resolve()
        read_root = read_root.resolve()
        try:
            cwd.relative_to(read_root)
        except ValueError:
            raise ToolError("refusing to run a scanner outside the asset") from None
        home = scratch / "home"
        home.mkdir()
        command = [
            bwrap,
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",  # noqa: S108  sandbox tmpfs, not a host temp file
            "--bind",
            str(home),
            "/htw-home",
            "--setenv",
            "HOME",
            "/htw-home",
        ]
        if offline:
            command.append("--unshare-net")
        for system in _SYSTEM_DIRS:
            path = Path(system)
            if path.is_symlink():
                # /lib64 and /bin are symlinks into /usr on merged-/usr systems.
                # The dynamic linker is reached through those links.
                command += ["--symlink", os.readlink(system), system]
            elif path.is_dir():
                command += ["--ro-bind", system, system]
        run_env = {
            key: value
            for key, value in env.items()
            if key not in {"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"}
        }
        run_env["HOME"] = "/htw-home"
        self._bind_executable(command, argv, env, run_env)
        command += ["--ro-bind", str(read_root), str(read_root)]
        mounted: list[Path] = []
        for extra in writable:
            bound = _writable_mount(Path(extra), read_root)
            if bound is not None and bound not in mounted:
                mounted.append(bound)
                command += ["--bind", str(bound), str(bound)]
        for name in self._passthrough:
            bound = _cache_mount(env.get(name), read_root)
            if bound is not None:
                command += ["--bind", str(bound), str(bound)]
        command += ["--chdir", str(cwd), "--", *argv]
        return command, run_env

    def _bind_executable(
        self,
        command: list[str],
        argv: list[str],
        env: Mapping[str, str],
        run_env: dict[str, str],
    ) -> None:
        found = shutil.which(argv[0], path=env.get("PATH"))
        if found is None:
            return
        resolved = Path(found).resolve()
        if _under_system(resolved):
            return
        root = resolved.parent
        for parent in resolved.parents:
            if (parent / "pyvenv.cfg").is_file():
                root = parent
                break
            if parent == Path("/"):
                break
        if not _under_system(root):
            command += ["--ro-bind", str(root), str(root)]
        current = run_env.get("PATH", "")
        run_env["PATH"] = str(resolved.parent) + (os.pathsep + current if current else "")

    def _spawn(
        self,
        command: list[str],
        cwd: Path,
        env: dict[str, str],
        name: str,
        started: float,
        timeout: int,
        scratch: Path,
    ) -> CommandResult:
        out_path = scratch / "stdout"
        err_path = scratch / "stderr"
        sandboxed = Path(command[0]).name == "bwrap"
        with open(out_path, "wb") as out, open(err_path, "wb") as err:
            try:
                process = subprocess.Popen(
                    command,
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
            argv=tuple(command),
            returncode=process.returncode,
            stdout=out_path.read_text(encoding="utf-8", errors="replace"),
            stderr=err_path.read_text(encoding="utf-8", errors="replace"),
            duration_seconds=round(time.monotonic() - started, 3),
            sandboxed=sandboxed,
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


def _under_system(path: Path) -> bool:
    for system in _SYSTEM_DIRS:
        root = Path(system)
        if path == root or path.is_relative_to(root):
            return True
    return False


def _rejects(path: Path, read_root: Path) -> bool:
    """True when mounting `path` would expose the home directory or the whole machine."""
    if path == Path("/") or path == read_root or read_root.is_relative_to(path):
        return True
    home = Path.home().resolve()
    return path == home or home.is_relative_to(path) or _under_system(path)


def _writable_mount(path: Path, read_root: Path) -> Path | None:
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
    path = path.resolve()
    if not path.is_dir():
        path = path.parent
    if _rejects(path, read_root):
        # A report directory inside the asset is the one writable overlay we allow.
        if path != read_root and path.is_relative_to(read_root) and not _under_system(path):
            return path
        raise ToolError(f"refusing to make {path} writable in the scanner sandbox")
    return path


def _cache_mount(value: str | None, read_root: Path) -> Path | None:
    if not value or not value.startswith("/"):
        return None
    path = Path(value)
    if not path.is_dir():
        return None
    path = path.resolve()
    if _rejects(path, read_root):
        return None
    return path


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
