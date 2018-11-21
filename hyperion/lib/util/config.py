from os.path import expanduser
from enum import Enum


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


DEFAULT_TCP_PORT = "23081"

TMP_SLAVE_DIR = "/tmp/Hyperion/slave/components"
TMP_COMP_DIR = "/tmp/Hyperion/components"
TMP_LOG_PATH = "/tmp/Hyperion/log"
TMP_ENV_PATH = "/tmp/Hyperion/env"

SSH_CONFIG_PATH = "%s/.ssh/config" % expanduser("~")
"""File path of users standard SSH config"""

SSH_CONTROLMASTERS_PATH = "%s/.ssh/controlmasters" % expanduser("~")
"""File path to the SSH control master directory"""

CUSTOM_SSH_CONFIG_PATH = "/tmp/Hyperion/ssh-config"
"""File path to the custom SSH configuration file used in this module"""

SSH_CONNECTION_TIMEOUT = 4
"""How many Seconds to wait before an SSH connection attempt fails"""

FORMAT = "%(asctime)s: %(name)s %(funcName)20s() [%(levelname)s]:\t%(message)s"
"""Logger output formatting"""

DEFAULT_COMP_WAIT_TIME = 3.0
"""Default time to wait for a component to start"""

STATE_DESCRIPTION = {
    CheckState.RUNNING: 'RUNNING',
    CheckState.STOPPED: 'STOPPED',
    CheckState.UNREACHABLE: 'HOST UNREACHABLE',
    CheckState.NOT_INSTALLED: 'HYPERION NOT INSTALLED ON REMOTE',
    CheckState.DEP_FAILED: 'DEPENDENCY FAILED',
    CheckState.STARTED_BY_HAND: 'RUNNING BUT NOT STARTED BY HYPERION',
    CheckState.STOPPED_BUT_SUCCESSFUL: 'STOPPED BUT CHECK WAS SUCCESSFUL',
    CheckState.UNKNOWN: 'UNKNOWN'

}
"""Global string description dictionary for CheckStates"""

SHORT_STATE_DESCRIPTION = {
    CheckState.RUNNING: 'RUNNING',
    CheckState.STOPPED: 'STOPPED',
    CheckState.UNREACHABLE: 'UNREACHABLE',
    CheckState.NOT_INSTALLED: 'NOT INSTALLED',
    CheckState.DEP_FAILED: 'DEP FAILED',
    CheckState.STARTED_BY_HAND: 'STARTED EXTERNALLY',
    CheckState.STOPPED_BUT_SUCCESSFUL: 'STOPPED (BUT SUCCESSFUL)',
    CheckState.UNKNOWN: 'UNKNOWN'
}

URWID_ATTRIBUTE_FOR_STATE = {
    CheckState.RUNNING: 'running',
    CheckState.STOPPED: 'stopped',
    CheckState.UNREACHABLE: 'stopped',
    CheckState.NOT_INSTALLED: 'stopped',
    CheckState.DEP_FAILED: 'stopped',
    CheckState.STARTED_BY_HAND: 'other',
    CheckState.STOPPED_BUT_SUCCESSFUL: 'other',
    CheckState.UNKNOWN: 'other'
}

STATE_CHECK_BUTTON_STYLE = {
    CheckState.RUNNING: 'green',
    CheckState.STOPPED: 'red',
    CheckState.UNREACHABLE: 'red',
    CheckState.NOT_INSTALLED: 'red',
    CheckState.DEP_FAILED: 'darkred',
    CheckState.STARTED_BY_HAND: 'lightsalmon',
    CheckState.STOPPED_BUT_SUCCESSFUL: 'darkcyan'
}
"""Global check button color dictionary for CheckStates"""
