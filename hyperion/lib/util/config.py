import logging
from os.path import expanduser
from enum import Enum

from typing import Optional


class ExitStatus(Enum):
    """Enum providing information about exit status"""

    UNKNOWN_ERROR = -1
    FINE = 0
    CONFIG_NOT_FOUND = 1
    MISSING_CONFIG = 2
    ERRONEUS_CONFIG = 3
    SSH_FAILED = 4
    NO_MASTER_RUNNING = 5
    MISSING_PYQT_INSTALL = 6
    DEPENDENCY_RESOLUTION_ERROR = 7
    CONFIG_PARSING_ERROR = 8
    ENVIRONMENT_FILE_MISSING = 9
    MISSING_SSH_CONFIG = 10
    CONFIG_RESET_FAILED = 11
    MISSING_UI_INSTALL = 12
    PROGRAMM_NOT_FOUND = 127


class CheckState(Enum):
    """Enum that provides information about the status of a run check"""

    RUNNING = 0
    STOPPED = 1
    STOPPED_BUT_SUCCESSFUL = 2
    STARTED_BY_HAND = 3
    DEP_FAILED = 4
    UNREACHABLE = 5
    NOT_INSTALLED = 6
    UNKNOWN = 7


class StartState(Enum):
    """Enum that provides information about the start state of a component"""

    STARTED = 100
    ALREADY_RUNNING = 101
    FAILED = 102


class HostConnectionState(Enum):
    """Enum that provides information about the status of a host"""

    CONNECTED = 1
    DISCONNECTED = 2
    SSH_ONLY = 3

DEFAULT_THREADN = 4
"""Default number of threads for concurrent starting or stopping"""

DEFAULT_LOG_UMASK = 0
"""Default permission mask for log files (results in 0777)"""

DEFAULT_LOG_LEVEL = logging.INFO
"""Default log level for all modules"""

LOCAL_STAT_MONITOR_RATE = 1.
"""Rate at which local stats are fetched in amount per second"""

REMOTE_STAT_MONITOR_RATE = 1.
"""Rate at which remote stats are fetched in amount per second"""

MONITOR_REMOTE_STATS = True
"""Bool whether to monitor remote system stats."""

MONITOR_LOCAL_STATS = True
"""Bool whether to monitor local system stats."""

MONITORING_RATE = 1.
"""Rate in Hz at which the monitoring thread runs checks"""

SHOW_CHECK_OUTPUT = False
"""Bool whether to show check command output"""

SHELL_EXECUTABLE_PATH = "/bin/bash"
"""Path to shell executable"""

DEFAULT_TCP_PORT = 23081

TMP_SLAVE_DIR = "/tmp/Hyperion/slave/conf"
TMP_CONF_DIR = "/tmp/Hyperion/conf/"
TMP_LOG_PATH = "/tmp/Hyperion/log"
TMP_ENV_PATH = "/tmp/Hyperion/env"

SSH_CONFIG_PATH = f"{expanduser('~')}/.ssh/config"
"""File path of users standard SSH config"""

SSH_CONTROLMASTERS_PATH = f"{expanduser('~')}/.ssh/controlmasters"
"""File path to the SSH control master directory"""

CUSTOM_SSH_CONFIG_PATH = "/tmp/Hyperion/ssh-config"
"""File path to the custom SSH configuration file used in this module"""

SSH_CONNECTION_TIMEOUT = 4
"""How many Seconds to wait before an SSH connection attempt fails"""

FORMAT = "%(asctime)s: %(name)s %(funcName)20s() [%(levelname)s]: %(message)s"
"""Logger output formatting"""

FORMAT_ERR = "%(asctime)s: %(name)s %(funcName)20s() [%(levelname)s]: %(message)s (%(filename)s:%(lineno)d)"
"""Logger output formatting for errors"""


class CustomFormatter(logging.Formatter):
    """Custom log formatter with different formats for different levels"""

    FORMATS = {
        logging.DEBUG: FORMAT,
        logging.INFO: FORMAT,
        logging.WARNING: FORMAT,
        logging.ERROR: FORMAT_ERR,
        logging.CRITICAL: FORMAT_ERR,
    }

    def format(self, record: logging.LogRecord) -> str:
        """Applies format to a log record according to its severity.

        Parameters
        ----------
        record : LogRecord
            Log record to format.

        Returns
        -------
        str
            Formatted log record.
        """        
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


class ColorFormatter(CustomFormatter):
    """Colored log formatter adapted from https://stackoverflow.com/a/56944256"""

    grey = "\x1b[38;20m"
    green = "\x1b[32;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    FORMATS = {
        logging.DEBUG: green + FORMAT + reset,
        logging.INFO: grey + FORMAT + reset,
        logging.WARNING: yellow + FORMAT + reset,
        logging.ERROR: red + FORMAT_ERR + reset,
        logging.CRITICAL: bold_red + FORMAT_ERR + reset,
    }


DEFAULT_COMP_WAIT_TIME = 3.0
"""Default time to wait for a component to start"""

STATE_DESCRIPTION = {
    CheckState.RUNNING: "RUNNING",
    CheckState.STOPPED: "STOPPED",
    CheckState.UNREACHABLE: "HOST UNREACHABLE",
    CheckState.NOT_INSTALLED: "HYPERION NOT INSTALLED ON REMOTE",
    CheckState.DEP_FAILED: "DEPENDENCY FAILED",
    CheckState.STARTED_BY_HAND: "RUNNING BUT NOT STARTED BY HYPERION",
    CheckState.STOPPED_BUT_SUCCESSFUL: "STOPPED BUT CHECK WAS SUCCESSFUL",
    CheckState.UNKNOWN: "UNKNOWN",
}
"""Global string description dictionary for CheckStates"""

SHORT_STATE_DESCRIPTION = {
    CheckState.RUNNING: "RUNNING",
    CheckState.STOPPED: "STOPPED",
    CheckState.UNREACHABLE: "UNREACHABLE",
    CheckState.NOT_INSTALLED: "NO INSTALL",
    CheckState.DEP_FAILED: "DEP FAILED",
    CheckState.STARTED_BY_HAND: "STARTED EXT",
    CheckState.STOPPED_BUT_SUCCESSFUL: "STOPPED (OK)",
    CheckState.UNKNOWN: "UNKNOWN",
}

URWID_ATTRIBUTE_FOR_STATE = {
    CheckState.RUNNING: "running",
    CheckState.STOPPED: "stopped",
    CheckState.UNREACHABLE: "stopped",
    CheckState.NOT_INSTALLED: "stopped",
    CheckState.DEP_FAILED: "stopped",
    CheckState.STARTED_BY_HAND: "other",
    CheckState.STOPPED_BUT_SUCCESSFUL: "other",
    CheckState.UNKNOWN: "other",
}

STATE_CHECK_BUTTON_STYLE = {
    CheckState.RUNNING: "green",
    CheckState.STOPPED: "red",
    CheckState.UNREACHABLE: "red",
    CheckState.NOT_INSTALLED: "red",
    CheckState.DEP_FAILED: "darkred",
    CheckState.STARTED_BY_HAND: "lightsalmon",
    CheckState.STOPPED_BUT_SUCCESSFUL: "darkcyan",
}
"""Global check button color dictionary for CheckStates"""

SLAVE_HYPERION_SOURCE_PATH: Optional[str] = None
"""Option to source a specific env where hyperion is located on a slave"""

EMPTY_HOST_STATS = ["N/A", "N/A", "N/A"]
"""Empty host stats to set on a new connection."""