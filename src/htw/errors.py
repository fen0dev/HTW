"""Exception types and process exit codes."""

from __future__ import annotations

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_REFUSED = 2
EXIT_INCOMPLETE = 3


class HtwError(Exception):
    """Base class for errors that should be shown to the operator without a traceback."""

    exit_code = EXIT_REFUSED


class ConfigError(HtwError):
    """The scope/configuration file is missing, malformed or incomplete."""


class ScopeViolation(HtwError):
    """An action was requested that the scope file does not authorize."""


class KillSwitchEngaged(HtwError):
    """The global stop switch is set; no scanner may start or continue."""


class ToolError(HtwError):
    """An external scanner failed, timed out or produced unusable output."""

    exit_code = EXIT_INCOMPLETE
