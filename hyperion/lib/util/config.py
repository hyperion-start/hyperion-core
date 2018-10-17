from os.path import expanduser

TMP_SLAVE_DIR = "/tmp/Hyperion/slave/components"
TMP_COMP_DIR = "/tmp/Hyperion/components"
TMP_LOG_PATH = "/tmp/Hyperion/log"

SSH_CONFIG_PATH = "%s/.ssh/config" % expanduser("~")
"""File path of users standard SSH config"""

SSH_CONTROLMASTERS_PATH = "%s/.ssh/controlmasters" % expanduser("~")
"""File path to the SSH control master directory"""

CUSTOM_SSH_CONFIG_PATH = "/tmp/Hyperion/ssh-config"
"""File path to the custom SSH configuration file used in this module"""

SSH_CONNECTION_TIMEOUT = 1
"""How many Seconds to wait before an SSH connection attempt fails"""

FORMAT = "%(asctime)s: %(name)s %(funcName)20s() [%(levelname)s]:\t%(message)s"
"""Logger output formatting"""

DEFAULT_COMP_WAIT_TIME = 3.0
"""Default time to wait for a component to start"""