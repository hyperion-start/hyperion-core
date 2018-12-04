#! /usr/bin/env python
from libtmux import Server, Window
from yaml import load, dump
import logging
import os
import sys
import socket
import shutil
from psutil import Process, NoSuchProcess
from subprocess import call, Popen, PIPE
from threading import Lock
from time import sleep, time, gmtime, strftime
from lib.util.setupParser import Loader
from lib.util.depTree import Node, dep_resolve
from lib.monitoring.threads import LocalComponentMonitoringJob, RemoteComponentMonitoringJob, \
    HostMonitorJob, MonitoringThread, CancellationJob
import lib.util.exception as exceptions
import lib.util.config as config
import lib.util.events as events

is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as queue
else:
    import queue as queue

BASE_DIR = os.path.dirname(__file__)
"""Path to the directory this file is contained in"""

SCRIPT_CLONE_PATH = ("%s/bin/start_named_clone_session.sh" % BASE_DIR)
"""File path of the 'clone session' script"""

SCRIPT_SHOW_SESSION_PATH = ("%s/bin/show_session.sh" % BASE_DIR)
"""File path of the 'clone session' script"""


###################
# Logging
###################
def setup_log(window, filepath, comp_id, start_tee=True):
    """Redirect stdout and stderr of window to file.

    Rotate logs and ensure the log directory for a component with id `comp_id` exists, than,
    redirect the outputs of `window` to /dev/tty to undo the case that previous output was already redirected.
    After that redirect outputs to `file`.

    :param window: tmux reference to the window the component is being run in.
    :type window: Window
    :param filepath: filepath of the component log file
    :type filepath: str
    :param comp_id: Id of the component being run (name@host)
    :type comp_id: str
    :return: None
    """

    clear_log(filepath, comp_id)
    ensure_dir(filepath)

    if start_tee:
        # Reroute stderr to log file
        window.cmd("send-keys", "exec 2> >(exec tee -i -a '%s')" % filepath, "Enter")
        # Reroute stdout to log file
        window.cmd("send-keys", "exec 1> >(exec tee -i -a '%s')" % filepath, "Enter")
    window.cmd("send-keys", ('echo "#Hyperion component start: %s\\t$(date)"' % comp_id), "Enter")


def get_component_wait(comp):
    """Returns time to wait after component start (default of 5 seconds unless overwritten in configuration).

    :param comp: Component configuration
    :return: Component wait time
    :rtype: float
    """
    logger = logging.getLogger(__name__)
    logger.debug("Retrieving wait time of component %s" % comp['name'])
    if 'wait' in comp:
        logger.debug("Found %s seconds as wait time for %s" % (float(comp['wait']), comp['name']))
        return float(comp['wait'])
    else:
        logger.debug("No wait time for %s found, using default of %s seconds" %
                          (comp['name'], config.DEFAULT_COMP_WAIT_TIME))
        return config.DEFAULT_COMP_WAIT_TIME


def clear_log(file_path, comp_id):
    """If found rename the log at file_path to COMPONENTNAME_DATETIME.log.

    :param file_path: log file path
    :type file_path: str
    :param comp_id: Component id (name@host)
    :type comp_id: str
    :return: None
    """

    if os.path.isfile(file_path):
        directory = os.path.dirname(file_path)
        os.rename(file_path, "%s/%s-%s.log" % (directory, comp_id, strftime("%Y-%m-%d_%H-%M-%S", gmtime())))


def ensure_dir(file_path):
    """If not already existing, recursively create parent directory of file_path.

    :param file_path: log file path
    :type file_path: str
    :return: None
    """

    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)


def dump_config(conf):
    """Dumps configuration in a file called conf-result.yaml.

    :param conf: Configuration read from one or more yaml files
    :type conf: dict
    :return: None
    """
    with open('conf-result.yml', 'w') as outfile:
        dump(conf, outfile, default_flow_style=False)


class AbstractController(object):
    """Abstract controller class that defines basic controller variables and methods."""

    def __init__(self, configfile):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.configfile = configfile
        self.custom_env_path = None
        self.subscribers = []
        self.config = None
        self.session = None
        self.server = None
        self.dev_mode = True

    def _broadcast_event(self, event):
        """Put a given event in all registered subscriber queues.

        :param event: Event to broadcast
        :type event: events.BaseEvent
        :return: None
        """
        for subscriber in self.subscribers:
            subscriber.put(event)

    def _load_config(self, filename="default.yaml"):
        """Load configuration recursively from yaml file.

        :param filename: path to the configuration file.
        :type filename: str
        :return: None
        """

        try:
            with open(filename) as data_file:
                self.config = load(data_file, Loader)
        except IOError as e:
            self.logger.critical("No config file at '%s' found" % filename)
            raise e

        if 'env' in self.config and self.config.get('env'):
            env = self.config.get('env')
            if os.path.isfile(env):
                self.logger.debug("Custom env given as absolute path! Saving to config")
                self.custom_env_path = env
            elif os.path.isfile(os.path.join(os.path.dirname(filename), env)):
                self.logger.debug("Custom env given as relative path! Saving to config")
                self.custom_env_path = os.path.join(os.path.dirname(filename), env)
            else:
                self.logger.critical("Env file %s could not be found!" % env)
                raise exceptions.EnvNotFoundException("Env file %s could not be found!" % env)

    ###################
    # Component Management
    ###################
    def _run_component_check(self, comp):
        """Runs the component check defined in the component configuration and returns the exit state.

        :param comp: Component configuration
        :type comp: dict
        :return: Check exit state (fail = False / success = True).
        :rtype: bool
        """
        self.logger.debug("Running specific component check for %s" % comp['name'])

        shell_init = ''
        if self.custom_env_path:
            shell_init = '. %s; ' % self.custom_env_path

        p = Popen('%s%s' % (shell_init, comp['cmd'][1]['check']), shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)

        while p.poll() is None:
            sleep(.5)

        if p.returncode == 0:
            self.logger.debug("Check returned true")
            return True
        else:
            self.logger.debug("Check returned false")
            return False

    def _check_local_component(self, comp):
        """Check if a local component is running and return the corresponding CheckState.

        :param comp: Component configuration
        :type comp: dict
        :return: tuple of pid and component status. If the component is not running, the pid is 0.
        :rtype: (int, config.CheckState)
        """
        logger = self.logger

        logger.debug("Running component check for %s" % comp['id'])
        check_available = len(comp['cmd']) > 1 and 'check' in comp['cmd'][1]
        window = self._find_window(comp['id'])

        pid = 0

        if window:
            w_pid = self._get_window_pid(window)
            logger.debug("Found window pid: %s" % w_pid)

            # May return more child pids if logging is done via tee (which then was started twice in the window too)
            procs = []
            for entry in w_pid:
                procs.extend(Process(entry).children(recursive=True))

            pids = []
            for p in procs:
                if p.name() != 'tee':
                    pids.append(p.pid)
            logger.debug("Window is running %s non-logger child processes: %s" % (len(pids), pids))

            if len(pids) < 1:
                logger.debug("Main process has finished. Running custom check if available")
                if check_available and self._run_component_check(comp):
                    logger.debug("Process terminated but check was successful")
                    ret = config.CheckState.STOPPED_BUT_SUCCESSFUL
                else:
                    logger.debug("Check failed or no check available: returning false")
                    ret = config.CheckState.STOPPED
            elif check_available and self._run_component_check(comp):
                logger.debug("Check succeeded")
                pid = pids[0]
                ret = config.CheckState.RUNNING
            elif not check_available:
                logger.debug("No custom check specified and got sufficient pid amount: returning true")
                pid = pids[0]
                ret = config.CheckState.RUNNING
            else:
                logger.debug("Check failed: returning false")
                ret = config.CheckState.STOPPED
        else:
            logger.debug("%s window is not running. Running custom check" % comp['name'])
            if check_available and self._run_component_check(comp):
                logger.debug("Component was not started by Hyperion, but the check succeeded")
                ret = config.CheckState.STARTED_BY_HAND
            else:
                logger.debug("Window not running and no check command is available or it failed: returning false")
                ret = config.CheckState.STOPPED

        return pid, ret

    def _get_window_pid(self, window):
        """Returns pid of the tmux window process.

        :param window: tmux window
        :type window: Window
        :return: pid of the window as list
        :rtype: list of int
        """
        self.logger.debug("Fetching pids of window %s" % window.name)
        r = window.cmd('list-panes',
                       "-F #{pane_pid}")
        return [int(p) for p in r.stdout]

    def get_component_by_id(self, comp_id):
        """Return component configuration by providing only the name.

        :param comp_id: Component name
        :type comp_id: str
        :return: Component configuration
        :rtype: dict
        :raises exceptions.ComponentNotFoundException: If component was not found
        """
        self.logger.debug("Searching for %s in components" % comp_id)
        for group in self.config['groups']:
            for comp in group['components']:
                if comp['id'] == comp_id:
                    self.logger.debug("Component '%s' found" % comp_id)
                    return comp
        raise exceptions.ComponentNotFoundException(comp_id)

    ###################
    # TMUX
    ###################
    def kill_session_by_name(self, name):
        """Kill tmux session by name.

        :param name: Name of the session to be killed
        :type name: str
        :return: None
        """
        self.logger.debug("Killing session by name %s" % name)
        session = self.server.find_where({
            "session_name": name
        })
        session.kill_session()

    def _kill_window(self, window):
        """Kill tmux window by reference.

        :param window: Window to be killed
        :type window: Window
        :return: None
        """
        self.logger.info("Killing window by name %s" % window.name)
        window.cmd("send-keys", "", "C-c")
        window.kill_window()

    def _start_window(self, window, comp, log_file):
        """Execute cmd in window.

        Mainly used to run a component start command in its designated window

        :param window: Window the component will be started in
        :type window: Window
        :param comp: Component configuration
        :type comp: dict
        :param log_file: log file path
        :type log_file: str
        :return: None
        """

        comp_id = comp['id']
        tee_count = 0

        pid = self._get_window_pid(window)
        procs = []
        for entry in pid:
            procs.extend(Process(entry).children(recursive=True))

        for proc in procs:
            if proc.name() == 'tee' and proc.is_running():
                tee_count+=1
            if proc.name() != 'tee' and proc.is_running():
                try:
                    self.logger.debug("Killing leftover child process %s" % proc.name())
                    proc.terminate()
                except NoSuchProcess:
                    pass

        self.logger.debug("Rotating log for %s" % comp_id)
        if tee_count == 2:
            setup_log(window, log_file, comp_id, False)
        else:
            setup_log(window, log_file, comp_id)

        if self.custom_env_path:
            self.logger.debug("Sourcing custom environment for %s" % comp_id)
            cmd = ". %s" % self.custom_env_path
            self._wait_until_window_not_busy(window)
            window.cmd("send-keys", cmd, "Enter")

        self._wait_until_window_not_busy(window)
        self.logger.debug("Running start command for %s" % comp_id)
        window.cmd("send-keys", comp['cmd'][0]['start'], "Enter")

    def _find_window(self, window_name):
        """Return window by name (None if not found).

        :param window_name: Window name
        :type window_name: str
        :return: Window with name `window_name`
        :rtype: Window or None
        """

        window = self.session.find_where({
            "window_name": window_name
        })
        return window

    def _send_main_session_command(self, cmd):
        """Send command to the main window of the master session.

        `Session.cmd` sends the command to the currently active window of the session, and when issuing commands to the
        session, usually it is not intended to interact with component windows thus this functions fetches the main
        window and calls the `cmd` function on it.

        :param cmd: Command to execute
        :type cmd: str
        :return: None
        """
        self.logger.debug("Sending command to master session main window: %s" % cmd)
        window = self._find_window('Main')

        self._wait_until_window_not_busy(window)
        window.cmd("send-keys", cmd, "Enter")
        self._wait_until_window_not_busy(window)

    def _wait_until_main_window_not_busy(self):
        """Blocks until main window of the master session has no child process left running.

        :return: None
        """

        window = self._find_window('Main')
        self._wait_until_window_not_busy(window)

    def _wait_until_window_not_busy(self, window):
        """Checks whether the passed window is busy executing a process and blocks until it is not busy anymore.

        :return: None
        """

        self.logger.debug("Waiting until window '%s' has no running child processes left ..." % window.name)
        while self._is_window_busy(window):
            sleep(0.5)
        self.logger.debug("... window '%s' is not busy anymore" % window.name)

    def _is_window_busy(self, window):
        """Checks whether the window has at least one running child process (excluding tee processes).

        :param window: Window to be checked
        :return: True if window is busy, False if not
        :rtype: bool
        """

        pid = self._get_window_pid(window)

        procs = []
        for entry in pid:
            procs.extend(Process(entry).children(recursive=True))

        for p in procs:
            try:
                if p.is_running() and p.name() != 'tee':
                    self.logger.debug("Running child process: %s" % p.name())
                    return True
            except NoSuchProcess:
                pass

        return False


class ControlCenter(AbstractController):
    """Controller class that is able to handle a master session."""

    def __init__(self, configfile=None, monitor_enabled=False):
        """Sets up the ControlCenter

        Initializes an empty node dict, an empty host_list dict, creates a queue for monitor jobs and a monitoring
        thread that is started right away and sets a handler for signals. After that the configuration file is loaded
        and a master session with a main window is created if not already existing.

        :param configfile: Path to the configuration to initialize
        :type configfile: str
        :param monitor_enabled: Whether the monitoring thread should be launched or not
        :type monitor_enabled: bool
        """

        super(ControlCenter, self).__init__(configfile)
        self.nodes = {}
        self.host_list = {
            '%s' % socket.gethostname(): True
        }
        self.host_list_lock = Lock()
        self.monitor_queue = queue.Queue()
        self.mon_thread = MonitoringThread(self.monitor_queue)
        if monitor_enabled:
            self.mon_thread.start()

        if configfile:
            try:
                self._load_config(configfile)
            except IOError:
                self.cleanup(status=1)
            except exceptions.EnvNotFoundException:
                self.cleanup(status=1)
            self.session_name = self.config["name"]

            self.logger.info("Loading config was successful")

            self.server = Server()

            if self.server.has_session(self.session_name):
                self.session = self.server.find_where({
                    "session_name": self.session_name
                })

                self.logger.info('found running session by name "%s" on server' % self.session_name)
            else:
                self.logger.info('starting new session by name "%s" on server' % self.session_name)
                self.session = self.server.new_session(
                    session_name=self.session_name,
                    window_name="Main"
                )
        else:
            self.config = None

    ###################
    # Setup
    ###################
    def init(self):
        """Initialize the controller.

        Sets up master ssh connections to all used hosts, copies components to them if they are reachable and computes a
        dependency tree for all used components.

        :return: None
        """
        if not self.config:
            self.logger.error(" Config not loaded yet!")

        else:
            self._setup_ssh_config()

            for group in self.config['groups']:
                for comp in group['components']:
                    self.logger.debug("Checking component '%s' in group '%s' on host '%s'" %
                                      (comp['name'], group['name'], comp['host']))
                    comp['id'] = "%s@%s" % (comp['name'], comp['host'])

                    try:
                        if comp['host'] != "localhost" and not self.run_on_localhost(comp):
                            if comp['host'] not in self.host_list:
                                if self._establish_master_connection(comp['host']):
                                    self.logger.info("Master connection to %s established!" % comp['host'])
                            if self.host_list.get(comp['host']) is not None:
                                self._copy_component_to_remote(comp, comp['host'])
                            else:
                                self.logger.debug("Not copying because host %s is not reachable: %s" %
                                                  (comp['host'], self.host_list.get(comp['name'])))
                    except exceptions.HostUnknownException as ex:
                        self.logger.error(ex.message)

            #if self.dev_mode:
            dump_config(self.config)

            try:
                self.set_dependencies()
            except exceptions.UnmetDependenciesException or exceptions.CircularReferenceException as ex:
                logging.debug("Error while setting up dependency tree. Initiating shutdown")
                self.cleanup(True, 1)

            if self.custom_env_path:
                self.logger.debug("Sourcing custom environment in main window of master session")
                cmd = ". %s" % self.custom_env_path
                self._send_main_session_command(cmd)

    def set_dependencies(self):
        """Parses all components constructing a dependency tree.

        :raises exception.UnmetDependencyException: If a component has an unmet dependency
        :return: None
        """
        unmet_deps = False

        for group in self.config['groups']:
            for comp in group['components']:
                self.nodes[comp['id']] = Node(comp)

        # Add a pseudo node that depends on all other nodes, to get a starting point to be able to iterate through all
        # nodes with simple algorithms
        master_node = Node({'id': 'master_node'})
        for id in self.nodes:
            node = self.nodes.get(id)

            # Add edges from each node to pseudo node
            master_node.add_edge(node)

            # Add edges based on dependencies specified in the configuration
            if "depends" in node.component:
                for dep in node.component['depends']:
                    if dep in self.nodes:
                        node.add_edge(self.nodes[dep])
                    else:
                        self.logger.error("Unmet dependency: '%s' for component '%s'!" % (dep, node.comp_id))
                        unmet_deps = True
        self.nodes['master_node'] = master_node

        # Test if starting all components is possible
        try:
            node = self.nodes.get('master_node')
            res = []
            unres = []
            dep_resolve(node, res, unres)
            dep_string = ""
            for node in res:
                if node is not master_node:
                    dep_string = "%s -> %s" % (dep_string, node.comp_id)
            self.logger.debug("Dependency tree for start all: %s" % dep_string)
        except exceptions.CircularReferenceException as ex:
            self.logger.error("Detected circular dependency reference between %s and %s!" % (ex.node1, ex.node2))
            raise ex
        if unmet_deps:
            raise exceptions.UnmetDependenciesException()

    def _copy_component_to_remote(self, comp, host):
        """Copies `comp` to `TMP_SLAVE_DIR` on the remote host `host`.

        To do so `comp` gets temporarily saved as standalone configfile on the local machine (in `TMP_COMP_DIR`) and
        then scpd to `TMP_SLAVE_DIR` on `host` (after ensuring the containing directory exists via mkdir -p invocation
        over ssh in the main window of the master session).

        :param comp: Component to copy
        :type comp: dict
        :param host: Host to copy the component to
        :type host: str
        :return: None
        """

        comp_id = comp['id']

        self.logger.debug("Saving component to tmp")
        tmp_comp_path = ('%s/%s.yaml' % (config.TMP_COMP_DIR, comp_id))
        ensure_dir(tmp_comp_path)

        if self.custom_env_path:
            comp['env'] = "%s/%s" % (config.TMP_ENV_PATH, os.path.basename(self.custom_env_path))

        with open(tmp_comp_path, 'w') as outfile:
            dump(comp, outfile, default_flow_style=False)

            self.logger.debug('Copying component "%s" to remote host "%s"' % (comp_id, host))
            cmd = ("ssh -F %s %s 'mkdir -p %s' && scp %s %s:%s/%s.yaml" %
                   (config.CUSTOM_SSH_CONFIG_PATH, host, config.TMP_SLAVE_DIR, tmp_comp_path, host,
                    config.TMP_SLAVE_DIR, comp_id))
            self._send_main_session_command(cmd)

    def _copy_env_file(self, host):
        """Copies a custom environment file to source to the remote host `host` if it was specified in the config.

        :param host: Host to copy the file to.
        :type host: str
        :return: None
        """

        if self.custom_env_path:
            self.logger.debug("Copying custom env file to %s" % host)
            cmd = ("ssh -F %s %s 'mkdir -p %s'" % (config.CUSTOM_SSH_CONFIG_PATH, host, config.TMP_ENV_PATH))
            cmd = "%s && scp %s %s:%s/" % (cmd, os.path.abspath(self.custom_env_path), host, config.TMP_ENV_PATH)
            self._send_main_session_command(cmd)

    def _setup_ssh_config(self):
        """Creates an ssh configuration that is saved to `CUSTOM_SSH_CONFIG_PATH`.

        The user config in `SSH_CONFIG_PATH` is copied to `CUSTOM_SSH_CONFIG_PATH` and then appends the lines enabling
        master connections for all hosts to it. This is done in order to use the master connection feature without
        tempering with the users standard configuration.

        :return: None
        """
        try:
            self.logger.debug("Trying to copy ssh config from %s to %s" % (config.SSH_CONFIG_PATH,
                                                                           config.CUSTOM_SSH_CONFIG_PATH))
            ensure_dir(config.CUSTOM_SSH_CONFIG_PATH)
            ensure_dir('%s/somefile' % config.SSH_CONTROLMASTERS_PATH)
            shutil.copy(config.SSH_CONFIG_PATH, config.CUSTOM_SSH_CONFIG_PATH)
        except IOError:
            self.logger.critical("Could not copy ssh config! Make sure you have a config in your users .ssh folder!")
            self.cleanup(True, 1)

        try:
            conf = open(config.CUSTOM_SSH_CONFIG_PATH, 'a')
            conf.write("Host *\n    ControlMaster yes\n    ControlPath ~/.ssh/controlmasters/%C")
        except IOError:
            self.logger.error("Could not append to custom ssh config!")

    def _establish_master_connection(self, hostname):
        """Create a master ssh connection to host `hostname` in a dedicated window.

        The pid of the ssh session is put into the monitoring thread to have a means to check if the connection still
        exists. Also `host` is added to the list of known hosts with its current status.

        :param hostname: Host to establish a connection with
        :type hostname: str
        :return: Whether establishing the connection was successful or not
        :rtype: bool
        """

        self.logger.debug("Establishing master connection to host %s" % hostname)

        cmd = 'ssh -F %s %s -o BatchMode=yes -o ConnectTimeout=%s' % (config.CUSTOM_SSH_CONFIG_PATH,
                                                                      hostname, config.SSH_CONNECTION_TIMEOUT)

        is_up = True if os.system('ping -w2 -c 1 %s > /dev/null' % hostname) is 0 else False
        if not is_up:
            self.logger.error("Host %s is not reachable!" % hostname)

            self.host_list_lock.acquire()
            self.host_list[hostname] = None
            self.host_list_lock.release()
            return False

        window = self._find_window('ssh-%s' % hostname)
        if window:
            self.logger.debug("Connecting to '%s' in old window" % hostname)

            if self._is_window_busy(window):
                self.logger.debug("Old connection still alive. No need to reconnect")
            else:
                self.logger.debug("Old connection died. Reconnecting to host")
                window.cmd("send-keys", cmd, "Enter")

        else:
            self.logger.debug("Connecting to '%s' in new window" % hostname)
            window = self.session.new_window('ssh-%s' % hostname)
            window.cmd("send-keys", cmd, "Enter")

        t_end = time() + config.SSH_CONNECTION_TIMEOUT

        pid = self._get_window_pid(window)
        pids = []

        while time() < t_end:
            procs = []
            for entry in pid:
                procs.extend(Process(entry).children(recursive=True))

            for p in procs:
                try:
                    if p.name() == 'ssh':
                        pids.append(p.pid)
                except NoSuchProcess:
                    pass
            if len(pids) > 0:
                break

        if len(pids) < 1:
            self.host_list_lock.acquire()
            self.host_list[hostname] = None
            self.host_list_lock.release()
            return False

        ssh_proc = Process(pids[0])
        # Add host to known list with process to poll from
        self.host_list_lock.acquire()
        self.host_list[hostname] = ssh_proc
        self.host_list_lock.release()

        self.logger.debug("Testing if connection was successful")
        if ssh_proc.is_running():
            self.logger.debug("SSH process still running. Connection was successful")
            self.logger.debug("Adding ssh master to monitor queue")
            self.monitor_queue.put(HostMonitorJob(pids[0], hostname, self.host_list, self.host_list_lock))
            self.logger.debug("Copying env files to remote %s" % hostname)
            self._copy_env_file(hostname)
            return True
        else:
            self.logger.debug("SSH process has finished. Connection was not successful. Check if an ssh connection "
                              "is allowed or if the certificate has to be renewed")
            return False

    def reconnect_with_host(self, hostname):
        """Re-establish master connection to host `hostname`

        :param hostname: Host to connect to
        :type hostname: str
        :return: Whether establishing the connection was successful or not
        :rtype: bool
        """

        # Check if really necessary
        self.logger.debug("Reconnecting with %s" % hostname)
        proc = self.host_list.get(hostname)
        if proc is not None:
            self.logger.debug("Killing off leftover process")
            proc.kill()

        # Start new connection
        if self._establish_master_connection(hostname):
            # Sync components
            self.logger.debug("Syncing components to remote host")
            for group in self.config['groups']:
                for comp in group['components']:
                    if comp['host'] == hostname:
                        self._copy_component_to_remote(comp, comp['host'])
            return True
        else:
            return False

    def add_subscriber(self, subscriber_queue):
        """Add a queue to the list of subscribers for manager and monitoring thread events.

        :param subscriber_queue: Event queue of the subscriber
        :type subscriber_queue: queue.Queue
        :return: None
        """
        self.subscribers.append(subscriber_queue)
        self.mon_thread.add_subscriber(subscriber_queue)

    def remove_subscriber(self, subscriber_queue):
        """Remove a queue from the list of subscribers for manager and monitoring thread events.

        :param subscriber_queue: Event queue of the subscriber
        :type subscriber_queue: queue.Queue
        :return: None
        """
        self.subscribers.remove(subscriber_queue)
        self.mon_thread.remove_subscriber(subscriber_queue)

    ###################
    # Stop
    ###################
    def stop_component(self, comp):
        """Stop component `comp`.

        Invokes the lower level stop function depending on whether the component is run locally or on a remote host.

        :param comp: Component to stop
        :type comp: dict
        :return: None
        """

        self._broadcast_event(events.StoppingEvent(comp['id']))

        self.logger.debug("Removing %s from process monitoring list" % comp['id'])
        self.monitor_queue.put(CancellationJob(0, comp['id']))

        try:
            on_localhost = self.run_on_localhost(comp)
        except exceptions.HostUnknownException:
            self.logger.warn("Host '%s' is unknown and therefore not reachable!" % comp['host'])
            return
        if comp['host'] != 'localhost' and not on_localhost:
            self.logger.info("Stopping remote component '%s'" % comp['id'])
            self._stop_remote_component(comp)
        else:
            self.logger.info("Stopping local component '%s'" % comp['id'])
            window = self._find_window(comp['id'])

            if window:
                self.logger.debug("window '%s' found running" % comp['id'])
                self.logger.debug("Shutting down window...")
                self._kill_window(window)
                self.logger.debug("... done!")
            else:
                self.logger.warning("Component '%s' seems to already be stopped" % comp['id'])

    def _stop_remote_component(self, comp):
        """Stops remote component `comp`.

        Via ssh Hyperion is executed on the remote host in slave mode with the --kill option.

        :param comp: Component to stop
        :type comp: dict
        :return: None
        """

        comp_name = comp['name']
        host = comp['host']
        # invoke Hyperion in slave kill mode on remote host
        if not self.host_list[host]:
            self.logger.error("Host %s is unreachable. Can not stop component %s" % (host, comp_name))
            return

        cmd = ("ssh -F %s %s 'hyperion --config %s/%s.yaml slave --kill'" % (
            config.CUSTOM_SSH_CONFIG_PATH, host, config.TMP_SLAVE_DIR, comp_name))
        self._send_main_session_command(cmd)

    ###################
    # Start
    ###################
    def start_component(self, comp):
        """Invoke dependency based start of component `comp`.

        Traverses the path of dependencies and invokes a call to ``start_component_without_deps`` for all found
        dependencies before calling it for `comp`.

        :param comp: Component to start
        :type comp: dict
        :return: Information on the start process
        :rtype: config.StartState
        """
        failed_comps = {}
        node = self.nodes.get(comp['id'])
        res = []
        unres = []
        dep_resolve(node, res, unres)
        for node in res:
            if node.comp_id != comp['id']:
                self.logger.debug("Checking and starting %s" % node.comp_id)
                state = self.check_component(node.component)

                if (state is config.CheckState.STOPPED_BUT_SUCCESSFUL or
                        state is config.CheckState.STARTED_BY_HAND or
                        state is config.CheckState.RUNNING):
                    self.logger.debug("Component '%s' is already running, skipping to next in line" % comp['id'])
                else:
                    self.logger.debug("Start component '%s' as dependency of '%s'" % (node.comp_id, comp['id']))
                    self.start_component_without_deps(node.component)

                    # Wait component time for startup
                    sleep(get_component_wait(node.component))

                    tries = 0
                    while True:
                        self.logger.debug("Checking %s resulted in checkstate %s" % (node.comp_id,
                                                                                     config.STATE_DESCRIPTION.get(state)))
                        state = self.check_component(node.component)
                        if (state is config.CheckState.RUNNING or
                                state is config.CheckState.STOPPED_BUT_SUCCESSFUL):
                            self.logger.debug("Dep '%s' success")
                            break
                        if tries > 3:
                            self._broadcast_event(events.CheckEvent(comp['id'], config.CheckState.DEP_FAILED))
                            failed_comps[node.comp_id] = state
                            failed_comps[comp['id']] = config.CheckState.DEP_FAILED
                            break
                        tries = tries + 1
                        sleep(.5)

        state = self.check_component(node.component)
        if (state is config.CheckState.STARTED_BY_HAND or
                state is config.CheckState.RUNNING):
            self.logger.warn("Component %s is already running. Skipping start" % comp['id'])
            return config.StartState.ALREADY_RUNNING
        else:
            if len(failed_comps) > 0:
                self.logger.warn("At least one dependency failed and the component is not running. Aborting start")
                failed_comps[comp['id']] = config.CheckState.DEP_FAILED
                self._broadcast_event(events.StartReportEvent(comp['id'], failed_comps))
                return config.StartState.FAILED
            else:
                self.logger.info("All dependencies satisfied, starting '%s'" % (comp['id']))
                self.start_component_without_deps(comp)
                sleep(get_component_wait(comp))
                ret = self.check_component(comp)
            if (ret is not config.CheckState.RUNNING and
                    ret is not config.CheckState.STOPPED_BUT_SUCCESSFUL):
                self.logger.warn("All dependencies satisfied, but start failed: %s!" % config.STATE_DESCRIPTION.get(ret))
                self._broadcast_event(events.StartReportEvent(comp['id'], {comp['id']: ret}))
                return config.StartState.FAILED
            return config.StartState.STARTED

    def start_component_without_deps(self, comp):
        """Chooses which lower level start function to use depending on whether the component is run on a remote host or not.

        :param comp: Component to start
        :type comp: dict
        :return: None
        """

        comp_id = comp['id']
        host = comp['host']

        self._broadcast_event(events.StartingEvent(comp_id))

        try:
            on_localhost = self.run_on_localhost(comp)
        except exceptions.HostUnknownException:
            self.logger.warn("Host '%s' is unknown and therefore not reachable!" % comp['host'])
            return

        if host != 'localhost' and not on_localhost:
            self.logger.info("Starting remote component '%s' on host '%s'" % (comp_id, host))
            self._start_remote_component(comp)
        else:
            log_file = ("%s/%s/latest.log" % (config.TMP_LOG_PATH, comp_id))
            window = self._find_window(comp_id)
            self.logger.info("Starting local component '%s'" % comp['id'])

            if window:
                self.logger.debug("Restarting '%s' in old window" % comp_id)
                self._start_window(window, comp, log_file)
            else:
                self.logger.debug("creating window '%s'" % comp_id)
                window = self.session.new_window(comp_id)
                self._start_window(window, comp, log_file)

    def _start_remote_component(self, comp):
        """Start component 'comp' on remote host.

        The remote component is started by invoking Hyperion over ssh in slave mode.

        :param comp: Component to start
        :type comp: dict
        :return: None
        """

        comp_name = comp['name']
        host = comp['host']
        # invoke Hyperion in slave mode on each remote host

        if not self.host_list[host]:
            self.logger.error("Hot %s is not reachable. Can not start component %s" % (host, comp_name))
            return

        cmd = ("ssh -F %s %s 'hyperion --config %s/%s.yaml slave'" % (
            config.CUSTOM_SSH_CONFIG_PATH, host, config.TMP_SLAVE_DIR, comp_name))
        self._send_main_session_command(cmd)

    def start_all(self):
        """Start all components ordered by dependecy.

        :return: None
        """
        comps = self.get_start_all_list()
        logger = self.logger
        failed_comps = {}

        for comp in comps:
            deps = self.get_dep_list(comp.component)
            failed = False

            for dep in deps:
                if dep.comp_id in failed_comps:
                    logger.debug("Comp %s failed, because dependency %s failed!" % (comp.comp_id, dep.comp_id))
                    failed = True

            if not failed:
                logger.debug("Checking %s" % comp.comp_id)
                ret = self.check_component(comp.component)
                if ret is config.CheckState.RUNNING or ret is config.CheckState.STARTED_BY_HAND:
                    logger.debug("Dep %s already running" % comp.comp_id)
                else:
                    tries = 0
                    logger.debug("Starting dep %s" % comp.comp_id)
                    self.start_component_without_deps(comp.component)
                    # Component wait time for startup
                    sleep(get_component_wait(comp.component))
                    while True:
                        sleep(.5)
                        ret = self.check_component(comp.component)
                        if (ret is config.CheckState.RUNNING or
                                ret is config.CheckState.STOPPED_BUT_SUCCESSFUL):
                            break
                        if tries > 10 or ret is config.CheckState.NOT_INSTALLED or ret is \
                                config.CheckState.UNREACHABLE:
                            logger.debug("Component %s failed, adding it to failed list" % comp.comp_id)
                            failed_comps[comp.comp_id] = ret
                            break
                        tries = tries + 1
            else:
                ret = self.check_component(comp.component)
                if ret is config.CheckState.STOPPED:
                    self._broadcast_event(events.CheckEvent(comp.comp_id, config.CheckState.DEP_FAILED))
                    failed_comps[comp.comp_id] = config.CheckState.DEP_FAILED
        self._broadcast_event(events.StartReportEvent('All components', failed_comps))

    def stop_all(self):
        """Stop all components ordered by dependency and run checks afterwards

        :return: None
        """
        comps = self.get_start_all_list()
        comps = list(reversed(comps))

        for comp in comps:
            self.stop_component(comp.component)

        for comp in comps:
            self.check_component(comp.component)

    ###################
    # Check
    ###################
    def check_component(self, comp):
        """Runs component check for `comp` and returns status.

        If `comp` is run locally the call is redirected to ``check_local_component``. If the `comp` is run on a remote
        host the function checks, if the host is reachable and on success issues an ssh command over the master
        connection which starts Hyperion in slave mode with the check option. The return value of the call is then
        interpreted for further processing.

        :param comp: Component to check
        :type comp: dict
        :return: State of the component
        :rtype: config.CheckState
        """
        try:
            if self.run_on_localhost(comp):
                ret = self._check_local_component(comp)

                pid = ret[0]
                if pid != 0:
                    self.monitor_queue.put(LocalComponentMonitoringJob(pid, comp['id']))
                ret_val = ret[1]
            else:
                self.logger.debug("Starting remote check")
                if self.host_list.get(comp['host']) is not None:
                    p = Popen(['ssh', '-F', config.CUSTOM_SSH_CONFIG_PATH, comp['host'],
                               'hyperion --config %s/%s.yaml slave -c' %
                               (config.TMP_SLAVE_DIR, comp['id'])], stdin=PIPE, stdout=PIPE, stderr=PIPE)

                    while p.poll() is None:
                        sleep(.5)
                    try:
                        pid = int(p.stdout.readlines()[-1])
                    except IndexError:
                        self.logger.error("Something went wrong on the remote host while checking!")
                        pid = 0

                    if pid != 0:
                        self.logger.debug("Got remote pid %s for component '%s'" % (pid, comp['id']))
                        self.monitor_queue.put(RemoteComponentMonitoringJob(pid, comp['id'], comp['host'],
                                                                            self.host_list))
                    try:
                        ret_val = config.CheckState(p.returncode)
                    except ValueError:
                        self.logger.error("Hyperion is not installed on host %s!" % comp['host'])
                        ret_val = config.CheckState.NOT_INSTALLED
                else:
                    self.logger.error("Host %s is unreachable. Can not run check for component %s!" % (comp['host'],
                                                                                                       comp['id']))
                    ret_val = config.CheckState.UNREACHABLE
        except exceptions.HostUnknownException:
            self.logger.warn("Host '%s' is unknown and therefore not reachable!" % comp['host'])
            ret_val = config.CheckState.UNREACHABLE
            pass

        # Create queue event for external notification and return for inner purpose
        self._broadcast_event(events.CheckEvent(comp['id'], ret_val))
        return ret_val

    ###################
    # CLI Functions
    ###################
    def list_components(self):
        """List all components used by the current configuration.

        :return: List of components
        :rtype: list of str
        """

        return [self.nodes.get(node).comp_name for node in self.nodes]

    def start_by_cli(self, comp_id):
        """Interface function for starting component by name `comp_name` from the cli.

        Logging information is provided on the INFO level.

        :param comp_id: Id of the component to start (name@host)
        :type comp_id: str
        :return: None
        """

        logger = logging.getLogger('EXECUTE-RESPONSE')

        try:
            comp = self.get_component_by_id(comp_id)
        except exceptions.ComponentNotFoundException as e:
            logger.warning(e.message)
            return

        logger.info("Starting component '%s' ..." % comp_id)
        ret = self.start_component(comp)
        if ret is config.StartState.STARTED:
            logger.info("Started component '%s'" % comp_id)
            sleep(get_component_wait(comp))
            ret = self.check_component(comp)
            logger.info("Check returned status: %s" % config.STATE_DESCRIPTION.get(ret))
        elif ret is config.StartState.FAILED:
            logger.info("Starting '%s' failed!" % comp_id)
        elif ret is config.StartState.ALREADY_RUNNING:
            logger.info("Aborted '%s' start: Component is already running!" % comp_id)

    def stop_by_cli(self, comp_id):
        """Interface function for stopping component by name `comp_name` from the cli.

        Logging information is provided on the INFO level.

        :param comp_id: Id of the component to stop (name@host)
        :type comp_id: str
        :return: None
        """

        logger = logging.getLogger('EXECUTE-RESPONSE')
        try:
            comp = self.get_component_by_id(comp_id)
        except exceptions.ComponentNotFoundException as e:
            logger.warning(e.message)
            return
        logger.info("Stopping component '%s' ..." % comp_id)
        self.stop_component(comp)
        sleep(2)
        ret = self.check_component(comp)
        logger.info("Check returned status: %s" % ret.name)

    def check_by_cli(self, comp_id):
        """Interface function for checking component by name `comp_name` from the cli.

        Logging information is provided on the INFO level.

        :param comp_id: Id of the component to check (name@host)
        :type comp_id: str
        :return: None
        """

        logger = logging.getLogger('EXECUTE-RESPONSE')
        logger.info("Checking component %s ..." % comp_id)
        try:
            comp = self.get_component_by_id(comp_id)
        except exceptions.ComponentNotFoundException as e:
            logger.warning(e.message)
            return
        ret = self.check_component(comp)
        logger.info("Check returned status: %s" % ret.name)

    def start_clone_session_and_attach(self, comp_id):
        """Interface function for show term of component by name `comp_name` from the cli.

        :param comp_id: Id of the component to show (name@host)
        :type comp_id: str
        :return: None
        """

        comp = self.get_component_by_id(comp_id)
        try:
            on_localhost = self.run_on_localhost(comp)
        except exceptions.HostUnknownException:
            self.logger.warn("Host '%s' is unknown and therefore not reachable!" % comp['host'])
            return

        if on_localhost:
            self.start_local_clone_session(comp)

            cmd = "%s '%s-clone-session'" % (SCRIPT_SHOW_SESSION_PATH, comp_id)
            call(cmd, shell=True)
        else:
            hostname = comp['host']
            self.start_remote_clone_session(comp)

            remote_cmd = ("%s '%s-clone-session'" % (SCRIPT_SHOW_SESSION_PATH, comp_id))
            cmd = "ssh -F %s %s 'bash -s' < %s" % (config.CUSTOM_SSH_CONFIG_PATH, hostname, remote_cmd)
            call(cmd, shell=True)

    def show_comp_log(self, comp_id):
        """Interface function for viewing the log of component by name `comp_name` from the cli. !!(NYI)!!

        :param comp_id: Id of the component whose log to show (name@host)
        :type comp_id: str
        :return: None
        """

        cmd = '/bin/bash -c "tail -n +1 -F %s/%s/latest.log"' % (config.TMP_LOG_PATH, comp_id)

        comp = self.get_component_by_id(comp_id)

        try:
           on_localhost = self.run_on_localhost(comp)
        except exceptions.HostUnknownException:
            self.logger.warn("Host '%s' is unknown and therefore not reachable!" % comp['host'])
            return

        if on_localhost:
            try:
                call(cmd, shell=True)
            except KeyboardInterrupt:
                pass
        else:
            hostname = comp['host']
            try:
                call("ssh -F %s %s '/bin/bash -s' < \"%s\"" % (config.CUSTOM_SSH_CONFIG_PATH, hostname, cmd),
                     shell=True)
            except KeyboardInterrupt:
                pass

    ###################
    # Dependency management
    ###################
    def get_dep_list(self, comp):
        """Get a list of all components that `comp` depends on.

        :param comp: Component to get dependencies from
        :type comp: dict
        :return: List of components
        :rtype: list of Node
        """

        node = self.nodes.get(comp['id'])
        res = []
        unres = []
        dep_resolve(node, res, unres)
        res.remove(node)

        return res

    def get_start_all_list(self):
        """Get a list of all components ordered by dependency (from dependency to depends on).

        :return: List of components
        :rtype: list of Node
        """

        node = self.nodes.get('master_node')
        res = []
        unres = []
        dep_resolve(node, res, unres)
        res.remove(node)

        return res

    ###################
    # Host related checks
    ###################
    def is_localhost(self, hostname):
        """Check if 'hostname' resolves to localhost.

        :param hostname: Name of host to check
        :type hostname: str
        :return: Whether 'host' resolves to localhost or not
        :rtype: bool
        """

        try:
            hn_out = socket.gethostbyname('%s' % hostname)
            if hn_out == '127.0.0.1' or hn_out == '127.0.1.1' or hn_out == '::1':
                self.logger.debug("Host '%s' is localhost" % hostname)
                return True
            else:
                self.logger.debug("Host '%s' is not localhost" % hostname)
                return False
        except socket.gaierror:
            raise exceptions.HostUnknownException("Host '%s' is unknown! Update your /etc/hosts file!" % hostname)

    def run_on_localhost(self, comp):
        """Check if component 'comp' is run on localhost or not.

        :param comp: Component to check
        :type comp: dict
        :return: Whether component is run on localhost or not
        :rtype: bool
        """
        try:
            return self.is_localhost(comp['host'])
        except exceptions.HostUnknownException as ex:
            raise ex

    ###################
    # TMUX
    ###################
    def kill_remote_session_by_name(self, name, host):
        """Kill tmux session by name 'name' on host 'host'

        :param name: Name of the session to kill
        :type name: str
        :param host: Host that the session runs on
        :type host: str
        :return: None
        """

        cmd = "ssh -F %s -t %s 'tmux kill-session -t %s'" % (config.CUSTOM_SSH_CONFIG_PATH, host, name)
        self._send_main_session_command(cmd)

    def start_local_clone_session(self, comp):
        """Start a local clone session of the master session and open the window of component `comp`.

        Because the libtmux library does not provide functions to achieve this, a bash script is run to automatize the
        process.

        :param comp: Component whose window is to be shown in the cloned session
        :type comp: dict
        :returns None
        """

        comp_id = comp['id']
        cmd = "%s '%s' '%s'" % (SCRIPT_CLONE_PATH, self.session_name, comp_id)
        call(cmd, shell=True)

    def start_remote_clone_session(self, comp):
        """Start a clone session of the remote slave session and open the window of component `comp`.

        Same as ``start_clone_session`` only that the bash script is fed into a ssh command issued over the main window
        of the master session.

        :param comp: Component whose window is to be shown in the clone session
        :type comp: dict
        :return:
        """

        session_name = 'slave-session'
        comp_id = comp['id']
        hostname = comp['host']

        remote_cmd = ("%s '%s' '%s'" % (SCRIPT_CLONE_PATH, session_name, comp_id))
        cmd = "ssh -F %s %s 'bash -s' < %s" % (config.CUSTOM_SSH_CONFIG_PATH, hostname, remote_cmd)
        self._send_main_session_command(cmd)

    ###################
    # Safe shutdown
    ###################
    def signal_handler(self, signum, frame):
        """Handler that invokes cleanup on a received signal.

        :param signum: Signal signum
        :type signum: int
        :param frame:
        :return: None
        """
        self.logger.debug("received signal %s. Running cleanup" % signum)
        self.cleanup()

    def cleanup(self, full=False, status=0):
        """Clean up for safe shutdown.

        Kills the monitoring thread and if full shutdown is requested also the ssh slave sessions and master connections
        and then shuts down the local tmux master session.

        :param full: Whether everything shall be shutdown or not
        :type full: bool
        :return: None
        """

        self.logger.info("Shutting down safely...")

        self.logger.debug("Killing monitoring thread")
        self.mon_thread.kill()

        if full:
            self.logger.info("Chose full shutdown. Killing remote and main sessions")

            for host in self.host_list:
                window = self._find_window('ssh-%s' % host)

                if window:
                    self.logger.debug("Killing remote slave session of host %s" % host)
                    self.kill_remote_session_by_name("slave-session", host)
                    self.logger.debug("Close ssh-master window of host %s" % host)
                    self._kill_window(window)

            self.kill_session_by_name(self.session_name)
        self.logger.info("... Done")
        exit(status)


class SlaveLauncher(AbstractController):
    """Controller class that performs a single slave execution task."""

    def __init__(self, configfile, kill_mode=False, check_mode=False):
        """Initializes slave.

        :param configfile: Path to configuration file (component configuration)
        :type configfile: str
        :param kill_mode: Whether the slave was started in kill mode or not
        :type kill_mode: bool
        :param check_mode: Whether the slave was started in check mode or not
        :type check_mode: bool
        """

        super(SlaveLauncher, self).__init__(configfile)
        self.kill_mode = kill_mode
        self.check_mode = check_mode
        if kill_mode:
            self.logger.info("started slave with kill mode")
        if check_mode:
            self.logger.info("started slave with check mode")
        self.server = Server()

        if self.server.has_session("slave-session"):
            self.session = self.server.find_where({
                "session_name": "slave-session"
            })

            self.logger.debug('found running slave session on server')
        elif not kill_mode and not check_mode:
            self.logger.debug('starting new slave session on server')
            self.session = self.server.new_session(
                session_name="slave-session"
            )

        else:
            self.logger.debug("No slave session found on server. Aborting")
            # Print fake pid
            print(0)
            exit(config.CheckState.STOPPED.value)

        if configfile:
            try:
                self._load_config(configfile)
            except IOError or exceptions.EnvNotFoundException:
                # Print fake pid
                print(0)
                exit(1)

            self.window_name = self.config['id']
            self.log_file = ("%s/%s/latest.log" % (config.TMP_LOG_PATH, self.window_name))
            ensure_dir(self.log_file)
        else:
            self.logger.error("No slave component config provided")

    def init(self):
        """Runs the mode specified by the slave execution call (start/stop or preparation for check)

        :return: None
        """
        if not self.config:
            self.logger.error(" Config not loaded yet!")
        elif not self.session:
            self.logger.error(" Init aborted. No session was found!")
        else:
            self.logger.debug(self.config)
            window = self._find_window(self.window_name)

            if window:
                self.logger.debug("window '%s' found running" % self.window_name)
                if self.kill_mode:
                    self.logger.debug("Shutting down window...")
                    self._kill_window(window)
                    self.logger.debug("... done!")
                else:
                    self.logger.debug("Starting '%s' in old window" % self.window_name)
                    self._start_window(window, self.config, self.log_file)
            elif not self.kill_mode:
                self.logger.debug("creating window '%s'" % self.window_name)
                window = self.session.new_window(self.window_name)
                self._start_window(window, self.config, self.log_file)

            else:
                self.logger.debug("There is no component running by the name '%s'. Exiting kill mode" %
                                  self.window_name)

    def run_check(self):
        """Run check for the current component.

        :return: Status of the component
        :rtype: config.CheckState
        """

        if not self.config:
            self.logger.error("Config not loaded yet!")
            exit(config.CheckState.STOPPED.value)
        elif not self.session:
            self.logger.error("Init aborted. No session was found!")
            exit(config.CheckState.STOPPED.value)

        ret = self._check_local_component(self.config)
        print(ret[0])
        exit(ret[1].value)
