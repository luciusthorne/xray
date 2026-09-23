class XRAYError(Exception):
    """Base class for expected XRAY errors."""

    exit_code = 1


class CLIError(XRAYError):
    """Invalid command-line usage."""

    exit_code = 2


class TargetError(XRAYError):
    """Invalid, missing, or inaccessible analysis target."""

    exit_code = 3


class FileError(XRAYError):
    """Filesystem-related failure."""

    exit_code = 3


class AnalysisError(XRAYError):
    """Failure while analyzing source code."""

    exit_code = 4
