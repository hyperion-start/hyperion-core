#! /usr/bin/env python
from libtmux.exc import LibTmuxException
from libtmux import Server, Window
from yaml import load, dump
import re
import logging
import os
import sys
import socket
import shutil
from psutil import Process, NoSuchProcess
from subprocess import call, Popen, PIPE
from threading import Lock
from time import sleep, time, strftime
from hyperion.lib.util.setupParser import Loader
from hyperion.lib.util.depTree import Node, dep_resolve
from hyperion.lib.monitoring.threads import StatMonitor, ComponentMonitor, CancellationJob, \
    HostMonitorJob, LocalComponentMonitoringJob, RemoteComponentMonitoringJob
import hyperion.lib.util.exception as exceptions
import hyperion.lib.util.config as config
import hyperion.lib.util.events as events
import hyperion.lib.util.actionSerializer as actionSerializer

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


def clear_log(file_path, log_name):
    """If found rename the log at file_path to e.g. COMPONENTNAME_TIME.log or 'server_TIME.log'.

    :param file_path: log file path
    :type file_path: str
    :param log_name: Name prefix of the log (current time will be appended)
    :type log_name: str
    :return: None
    """
    if os.path.isfile(file_path):
        directory = os.path.dirname(file_path)
        os.rename(file_path, "%s/%s_%s.log" % (directory, log_name, strftime("%H-%M-%S")))


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


def conf_preprocessing(conf, custom_env=None, exclude_tags=None):
    """Preprocess configuration file.

    - Set all component ids to comp_name@host
    - Interpret environment variables in hostnames

    :param conf: Config to preprocess
    :type conf: dict
    :param custom_env: Path to custom environment to source before trying to evaluate env variables
    :type custom_env: str
    :param exclude_tags: List of tags to exclude marked components from the config.
    :type exclude_tags: list of str
    :return: None
    """
    if custom_env:
        pipe = Popen(
            '. %s > /dev/null; env' % custom_env,
            stdout=PIPE,
            stderr=PIPE,
            shell=True,
            executable=config.SHELL_EXECUTABLE_PATH
        )
        data, err_lines = pipe.communicate()

        if err_lines and len(err_lines) > 0:
            if is_py2:
                err_lines = "".join(err_lines)
            else:
                err_lines = err_lines.decode("utf-8")
            logging.getLogger(__name__).critical(
                "Sourcing the custom environment file of this config returned with an error! "
                "Is it suitable for the selected shell executable ('%s')? "
                "Full stderr output:\n%s" % (config.SHELL_EXECUTABLE_PATH, err_lines)
            )

        keys = []
        values = []
        for line in data.splitlines():

            # Python version specifics
            if is_py2:
                entry = line.split("=", 1)
            else:
                entry = line.decode("utf-8").split("=", 1)

            if len(entry) == 2:
                keys.append(entry[0])
                values.append(entry[1])
            else:
                logging.debug("Line in env omitted: %s" % line)
        os.environ.update(dict(zip(keys, values)))

    pattern = '\\${(.*)}'
    pattern2 = '.*@\\${(.*)}'
    logging.debug("Pattern %s" % pattern)

    for group in conf['groups']:

        exclude_from_group = []
        for comp in group['components']:
            if exclude_tags and 'tags' in comp and comp.get('tags'):
                for tag in comp.get('tags'):
                    if tag in exclude_tags:
                        logging.getLogger(__name__).debug(
                            "Exclude component %s because of tag: %s" % (comp['name'], tag)
                        )
                        exclude_from_group.append(comp)
                        break

            host = comp['host']
            match = re.compile(pattern).match(host)

            if match and len(match.groups()) > 0:
                hn = os.environ.get(match.groups()[0])
                if not hn:
                    hn = match.groups()[0]
                comp['host'] = hn

            comp['id'] = "%s@%s" % (comp['name'], comp['host'])

            if 'depends' in comp:
                dep_index = 0
                for dep in comp['depends']:
                    match = re.compile(pattern2).match(dep)

                    if match and len(match.groups()) > 0:
                        host_var = os.environ.get(match.groups()[0])
                        if not host_var:
                            host_var = match.groups()[0]
                        comp['depends'][dep_index] = re.sub(pattern, host_var, dep)
                    dep_index += 1

        if len(exclude_from_group) > 0:
            c_list = group.get('components')
            [c_list.remove(comp) for comp in exclude_from_group]
            group['components'] = c_list


def get_component_cmd(component, cmd_type):
    """Retrieve component cmd from config.
    
    :param component: Compnent configuration
    :type component: dict
    :param cmd_type: Type of the cmd. Valid types are 'start', 'check' and 'stop'
    :type cmd_type: str
    :return: Command as string or None
    :rtype: str or None
    """
    if cmd_type is not 'start' and cmd_type is not 'check' and cmd_type is not 'stop':
        logging.getLogger(__name__).error("Unrecognized cmd type '%s' was given" % cmd_type)
        return

    cmd = None
    for ind, found in enumerate([True if cmd_type in cmd_tmp else "" for cmd_tmp in component['cmd']]):
        if found:
            cmd = component['cmd'][ind][cmd_type]
    return cmd


####################
# SSH Stuff
####################
def setup_ssh_config():
    """Creates an ssh configuration that is saved to `CUSTOM_SSH_CONFIG_PATH`.

    The user config in `SSH_CONFIG_PATH` is copied to `CUSTOM_SSH_CONFIG_PATH` and then appends the lines enabling
    master connections for all hosts to it. This is done in order to use the master connection feature without
    tempering with the users standard configuration.

    :return: Whether copying was successful or not
    :rtype: bool
    """
    logger = logging.getLogger(__name__)
    try:
        logger.debug("Trying to copy ssh config from %s to %s" % (config.SSH_CONFIG_PATH,
                                                                  config.CUSTOM_SSH_CONFIG_PATH))
        ensure_dir(config.CUSTOM_SSH_CONFIG_PATH)
        ensure_dir('%s/somefile' % config.SSH_CONTROLMASTERS_PATH)
        shutil.copy(config.SSH_CONFIG_PATH, config.CUSTOM_SSH_CONFIG_PATH)
    except IOError:
        logger.warn("Could not copy ssh config! Creating config from scratch!")
        if os.path.isfile(config.CUSTOM_SSH_CONFIG_PATH):
            os.remove(config.CUSTOM_SSH_CONFIG_PATH)
        os.mknod(config.CUSTOM_SSH_CONFIG_PATH)

    try:
        conf = open(config.CUSTOM_SSH_CONFIG_PATH, 'a')
        conf.write(
            "\n"
            "Host *\n"
            "    ControlMaster yes\n"
            "    ControlPath ~/.ssh/controlmasters/%C\n"
            "    ServerAliveInterval 10\n"
            "    PasswordAuthentication no"
        )
    except IOError:
        logger.error("Could not append to custom ssh config!")
        return False

    return True


class AbstractController(object):
    """Abstract controller class that defines basic controller variables and methods."""

    def __init__(self, configfile):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(config.DEFAULT_LOG_LEVEL)
        self.configfile = configfile
        self.monitor_queue = queue.Queue()
        self.custom_env_path = None
        self.subscribers = []
        self.stat_thread = StatMonitor()
        self.config = None
        self.session = None
        self.server = None
        self.dev_mode = True
        self.exclude_tags = None

    def broadcast_event(self, event):
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
        except exceptions.MissingComponentDefinitionException as err:
            self.logger.critical("File '%s' included by config not found!" % err)
            raise err

        self.session_name = self.config["name"]

        if 'env' in self.config and self.config.get('env'):
            env = self.config.get('env')
            if os.path.isfile(env):
                self.logger.debug("Custom env given as absolute path! Saving to config")
                self.custom_env_path = env
            elif os.path.isfile(os.path.join(os.path.dirname(filename), env)):
                self.logger.debug("Custom env given as relative path! Saving to config")
                self.custom_env_path = os.path.abspath(os.path.join(os.path.dirname(filename), env))
            else:
                self.logger.critical("Env file %s could not be found!" % env)
                raise exceptions.EnvNotFoundException("Env file %s could not be found!" % env)

        if 'exclude' in self.config and self.config.get('exclude'):
            self.exclude_tags = self.config.get('exclude')
            self.logger.info("Following tags are excluded by configuration: %s" % self.exclude_tags)

        if 'shell_path' in self.config and self.config.get('shell_path'):
            config.SHELL_EXECUTABLE_PATH = self.config.get('shell_path')
            self.logger.info("Changed default shell to: '%s'" % config.SHELL_EXECUTABLE_PATH)

        if 'monitoring_rate' in self.config and self.config.get('monitoring_rate'):
            config.MONITORING_RATE = self.config.get('monitoring_rate')
            self.logger.info("Changed monitoring rate to: '%s Hz'" % config.MONITORING_RATE)

        if 'verbose_checks' in self.config and self.config.get('verbose_checks'):
            config.SHOW_CHECK_OUTPUT = self.config.get('verbose_checks')
            self.logger.info("Set verbose checks to: '%s'" % config.SHOW_CHECK_OUTPUT)

        if 'local_monitor' in self.config:
            config.MONITOR_LOCAL_STATS = self.config.get('local_monitor')
            if not config.MONITOR_LOCAL_STATS:
                self.logger.info("Disabled local stat monitoring")

        if 'local_stat_rate' in self.config and self.config.get('local_stat_rate'):
            config.LOCAL_STAT_MONITOR_RATE = self.config.get('local_stat_rate')
            self.logger.info("Changed local stat monitoring rate to: '%s Hz'" % config.LOCAL_STAT_MONITOR_RATE)

        if 'remote_monitor' in self.config:
            config.MONITOR_REMOTE_STATS = self.config.get('remote_monitor')
            if not config.MONITOR_REMOTE_STATS:
                self.logger.info("Disabled remote stat monitoring")

        if 'remote_stat_rate' in self.config and self.config.get('remote_stat_rate'):
            config.REMOTE_STAT_MONITOR_RATE = self.config.get('remote_stat_rate')
            self.logger.info("Changed remote stat monitoring rate to: '%s Hz'" % config.REMOTE_STAT_MONITOR_RATE)

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

        check = get_component_cmd(comp, 'check')

        p = Popen(
            '%s%s' % (shell_init, check),
            shell=True,
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE,
            executable=config.SHELL_EXECUTABLE_PATH
        )

        while p.poll() is None:
            sleep(.5)

        if config.SHOW_CHECK_OUTPUT:
            self.logger.info(("Check output of '%s':\n%s" % (comp['id'], "".join(p.stdout.readlines()))))

            err_out_list = p.stderr.readlines()
            if len(err_out_list):
                self.logger.error(("'%s' check stderr:\n%s" % (comp['id'], "".join(err_out_list))))

        if p.returncode == 0:
            self.logger.debug("Check returned true")
            return True
        else:
            self.logger.debug("Check returned false")
            return False

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
    # start
    ###################
    def start_component_without_deps(self, comp):
        """Chooses which lower level start function to use depending on whether the component is run on a remote host or not.

        :param comp: Component to start
        :type comp: dict
        :return: None
        """
        comp_id = comp['id']
        host = comp['host']

        self.broadcast_event(events.StartingEvent(comp_id))

        try:
            on_localhost = self.run_on_localhost(comp)
        except exceptions.HostUnknownException:
            self.logger.warn("Host '%s' is unknown and therefore not reachable!" % comp['host'])
            return

        if host != 'localhost' and not on_localhost:
            self.logger.info("Starting remote component '%s' on host '%s'" % (comp_id, host))
            self._start_remote_component(comp)
        else:
            log_file = ("%s/localhost/component/%s/latest.log" % (config.TMP_LOG_PATH, comp_id))
            window = self._find_window(comp_id)
            self.logger.info("Starting local component '%s'" % comp['id'])

            if window:
                self.logger.debug("Restarting '%s' in old window" % comp_id)
                self._start_window(window, comp, log_file)
            else:
                self.logger.debug("creating window '%s'" % comp_id)
                window = self.session.new_window(window_name=comp_id, window_shell=config.SHELL_EXECUTABLE_PATH)
                self._start_window(window, comp, log_file)

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

        self.broadcast_event(events.StoppingEvent(comp['id']))

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

                if self._is_window_busy(window):
                    window.cmd("send-keys", "", "C-c")

                    end_t = time() + 10
                    wait = True
                    while wait:
                        if not self._is_window_busy(window):
                            wait = False
                        elif time() < end_t:
                            wait = False
                            self.logger.warn("C-c running for over 10 seconds, "
                                             "killing off process of window %s" % comp['id'])

                stop = get_component_cmd(comp, 'stop')
                if stop:
                    self.logger.debug("Found custom stop command")
                    window.cmd('send-keys', stop, "Enter")

                    end_t = time() + 2
                    wait = True
                    while wait:
                        if not self._is_window_busy(window):
                            wait = False
                        elif time() < end_t:
                            wait = False
                            self.logger.error("Stop command still running after 2 seconds... stop waiting for"
                                              "termination")

                self._kill_window(window)

                self.logger.debug("... done!")
            else:
                self.logger.warning("Component '%s' seems to already be stopped" % comp['id'])

    ###################
    # Check
    ###################
    def check_component(self, comp, broadcast=True):
        """Runs component check for `comp` and returns status.

        If `comp` is run locally the call is redirected to ``check_local_component``, if `comp` is run on a remote
        host the call is redirected to ``check_remote_component``.

        :param comp: Component to check
        :type comp: dict
        :param broadcast: Whether to broadcast the result to receivers or not
        :type broadcast: bool
        :return: State of the component
        :rtype: config.CheckState
        """
        try:
            on_localhost = self.run_on_localhost(comp)
            if on_localhost:
                ret = self._check_local_component(comp)

                pid = ret[0]
                if pid != 0:
                    self.monitor_queue.put(LocalComponentMonitoringJob(pid, comp['id']))
                ret_val = ret[1]
            else:
                ret_val = self._check_remote_component(comp)

        except exceptions.HostUnknownException:
            self.logger.warn("Host '%s' is unknown and therefore not reachable!" % comp['host'])
            ret_val = config.CheckState.UNREACHABLE
            pass

        # Create queue event for external notification and return for inner purpose
        # But only broadcast if it was a local check or no answer was received, because remote events will be
        # forwarded automatically
        if (ret_val == config.CheckState.UNREACHABLE or on_localhost) and broadcast:
            self.broadcast_event(events.CheckEvent(comp['id'], ret_val))
        return ret_val

    def _check_local_component(self, comp):
        """Check if a local component is running and return the corresponding CheckState.

        :param comp: Component configuration
        :type comp: dict
        :return: tuple of pid and component status. If the component is not running, the pid is 0.
        :rtype: (int, config.CheckState)
        """
        logger = self.logger

        logger.debug("Running component check for %s" % comp['id'])
        check_available = get_component_cmd(comp, 'check') is not None
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
            elif hostname == socket.gethostname():
                self.logger.debug("Host '%s' is localhost, but has no loopback definition!" % hostname)
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
            try:
                if proc.name() == 'tee' and proc.is_running():
                    tee_count+=1
                if proc.name() != 'tee' and proc.is_running():
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

        start = get_component_cmd(comp, 'start')
        window.cmd("send-keys", start, "Enter")

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

    ###################
    # TMUX SESSION CONTROL
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

    ####################
    # Do override in subclass
    ####################
    def cleanup(self, full, exit_status):
        """Cleanup function to override in subclasses.

        :param full: Full shutdown
        :type full: bool
        :param exit_status: Exit status for the application
        :type exit_status: config.ExitStatus
        :return: None
        """
        raise NotImplementedError

    def start_remote_clone_session(self, comp):
        raise NotImplementedError

    def add_subscriber(self, subscriber):
        raise NotImplementedError

    def start_all(self, force_mode=False):
        raise NotImplementedError

    def start_component(self, comp, force_mode=False):
        raise NotImplementedError

    def _start_remote_component(self, comp):
        raise NotImplementedError

    def stop_all(self):
        raise NotImplementedError

    def _stop_remote_component(self, comp):
        raise NotImplementedError

    def _check_remote_component(self, comp):
        raise NotImplementedError

    def reconnect_with_host(self, hostname):
        raise NotImplementedError

    def reload_config(self):
        raise NotImplementedError


class ControlCenter(AbstractController):
    """Controller class that is able to handle a master session."""

    def __init__(self, configfile=None, monitor_enabled=False, slave_server=None):
        """Sets up the ControlCenter

        Initializes an empty node dict, an empty host_list dict, creates a queue for monitor jobs and a monitoring
        thread that is started right away and sets a handler for signals. After that the configuration file is loaded
        and a master session with a main window is created if not already existing.

        :param configfile: Path to the configuration to initialize
        :type configfile: str
        :param monitor_enabled: Whether the monitoring thread should be launched or not
        :type monitor_enabled: bool
        :param slave_server: Socket server managing connection to slaves
        :type slave_server: hyperion.lib.networking.server.SlaveManagementServer
        """
        super(ControlCenter, self).__init__(configfile)
        self.slave_server = slave_server
        self.nodes = {}
        self.host_list = {
            '%s' % socket.gethostname(): True
        }
        self.host_list_lock = Lock()
        self.host_states = {
            '%s' % socket.gethostname(): config.HostState.CONNECTED
        }
        self.host_stats = {
            '%s' % socket.gethostname(): ['N/A', 'N/A', 'N/A']
        }
        self.monitor_queue = queue.Queue()
        self.mon_thread = ComponentMonitor(self.monitor_queue)
        if monitor_enabled:
            self.mon_thread.start()

        if configfile:
            try:
                self._load_config(configfile)
            except exceptions.MissingComponentDefinitionException:
                self.cleanup(status=config.ExitStatus.CONFIG_PARSING_ERROR)
            except IOError:
                self.cleanup(status=config.ExitStatus.CONFIG_PARSING_ERROR)
            except exceptions.EnvNotFoundException:
                self.cleanup(status=config.ExitStatus.ENVIRONMENT_FILE_MISSING)
            self.session_name = self.config["name"]

            self.logger.info("Loading config was successful")

            self.server = Server()

            session_ready = False
            try:
                if self.server.has_session(self.session_name):
                    self.session = self.server.find_where({
                        "session_name": self.session_name
                    })

                    self.logger.info('found running session by name "%s" on server' % self.session_name)
                    session_ready = True
            except LibTmuxException:
                self.logger.debug("Exception in libtmux while looking up sessions. Maybe no session is running. Trying "
                                  "to create a new one")

            if not session_ready:
                self.logger.info('starting new session by name "%s" on server' % self.session_name)
                self.session = self.server.new_session(
                    session_name=self.session_name,
                    window_name="Main"
                )

            if config.MONITOR_LOCAL_STATS:
                self.stat_thread.start()

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
            if not self.config.get('groups'):
                self.logger.critical("At least one group needs to be defined in your config!")
                self.cleanup(True, config.ExitStatus.CONFIG_PARSING_ERROR)

            if not setup_ssh_config():
                self.cleanup(True, config.ExitStatus.MISSING_SSH_CONFIG)
            conf_preprocessing(self.config, self.custom_env_path, self.exclude_tags)

            for group in self.config['groups']:
                for comp in group['components']:
                    try:
                        if comp['host'] != "localhost" and not self.run_on_localhost(comp):
                            if comp['host'] not in self.host_list:
                                if self._establish_master_connection(comp['host']):
                                    self.logger.info("Master connection to %s established!" % comp['host'])
                    except exceptions.HostUnknownException as ex:
                        self.logger.error(ex.message)

            try:
                self.set_dependencies()
            except (exceptions.UnmetDependenciesException, exceptions.CircularReferenceException) as ex:
                self.logger.debug("Error while setting up dependency tree. Initiating shutdown")
                self.cleanup(True, config.ExitStatus.DEPENDENCY_RESOLUTION_ERROR)

            if self.custom_env_path:
                self.logger.debug("Sourcing custom environment in main window of master session")
                cmd = ". %s" % self.custom_env_path
                self._send_main_session_command(cmd)

            if self.slave_server:
                self.slave_server.start()
            else:
                self.logger.critical("Slave server is None!")

            self.logger.debug("Starting slave on connected remote hosts")
            for host in self.host_list:
                if host and not self.is_localhost(host):
                    self.logger.debug("Starting slave on '%s'" % host)
                    self._start_remote_slave(host)

    def reload_config(self):
        """Try reloading configuration file. The old config is saved under a temporary variable that is discarded if
        reloading was successful, but restored if reloading failed at some point (missing file, or dependency errors)

        :return: None
        """
        old_conf = self.config.copy()
        try:
            self._load_config(self.configfile)
        except exceptions.MissingComponentDefinitionException as err:
            self.logger.error("Reloading failed with error! Included file '%s' not found!" % err.filename)
            self.config = old_conf
            return
        except IOError as err:
            self.logger.error("Reloading failed with error: %s" % err.message)
            self.config = old_conf
            return
        except exceptions.EnvNotFoundException:
            self.logger.error("Specified environment could not be found. Config reload aborted!")
            self.config = old_conf
            return

        conf_preprocessing(self.config, self.custom_env_path, self.exclude_tags)

        try:
            self.set_dependencies()
        except (exceptions.UnmetDependenciesException, exceptions.CircularReferenceException) as ex:
            self.logger.error("Error while setting up dependency tree. Rolling back to working config")
            self.config = old_conf
            try:
                self.set_dependencies()
            except (exceptions.UnmetDependenciesException, exceptions.CircularReferenceException) as ex:
                self.logger.critical("Resetting to old config failed!")
                self.cleanup(True, config.ExitStatus.CONFIG_RESET_FAILED)

        # Update hosts
        old_hostlist = self.host_list.copy()
        self.host_list = {'%s' % socket.gethostname(): True}
        self.host_states = {'%s' % socket.gethostname(): config.HostState.CONNECTED}

        for group in self.config['groups']:
            for comp in group['components']:
                try:
                    if comp['host'] != "localhost" and not self.run_on_localhost(comp):
                        if comp['host'] not in self.host_list:
                            if self._establish_master_connection(comp['host']):
                                self.logger.info("Master connection to %s established!" % comp['host'])
                except exceptions.HostUnknownException as ex:
                    self.logger.error(ex.message)

        unused_hosts = [k for k in old_hostlist if k not in self.host_list]
        if len(unused_hosts) > 0:
            self.logger.debug("Updated config removed hosts from setup - Killing unused remote slaves")
            for host in unused_hosts:
                self.slave_server.kill_slave_on_host(host)

        if self.custom_env_path:
            self.logger.debug("Sourcing custom environment in main window of master session")
            cmd = ". %s" % self.custom_env_path
            self._send_main_session_command(cmd)

        if self.slave_server and not self.slave_server.thread.is_alive():
            self.slave_server.start()

        messages = [actionSerializer.serialize_request('conf_reload', [])]

        for host in self.host_list:
            if host and not self.is_localhost(host):
                if host not in old_hostlist:
                    self.logger.debug("Starting slave on '%s'" % host)
                    self._start_remote_slave(host)
                else:
                    self.logger.debug("Updating slave on '%s'" % host)
                    self._start_remote_slave(host, messages)

        self.broadcast_event(events.ConfigReloadEvent(self.config, self.host_states))

    def _start_remote_slave(self, hostname, custom_messages=None):
        """Start slave manager on host 'hostname'.

        :param hostname: Host to start the slave manager on.
        :type hostname: str
        :param custom_messages: Optional messages to send to a newly connected or reconnected host.
        :type custom_messages: list of str
        :return: None
        """
        if not custom_messages:
            custom_messages = []

        window = self._find_window('ssh-%s' % hostname)
        config_path = "%s/%s.yaml" % (config.TMP_SLAVE_DIR, self.config['name'])

        self.host_stats[hostname] = ['N/A', 'N/A', 'N/A']

        if config.MONITOR_REMOTE_STATS:
            custom_messages.append(actionSerializer.serialize_request('stat_monitoring',
                                                                      [config.REMOTE_STAT_MONITOR_RATE]))

        if window and self.host_list[hostname] and self.slave_server:
            if self.slave_server.start_slave(hostname, config_path, self.config['name'], window, custom_messages):
                self.host_states[hostname] = config.HostState.CONNECTED
            else:
                self.host_states[hostname] = config.HostState.SSH_ONLY
        else:
            self.logger.error("No connection to remote '%s' - can not start slave manager" % hostname)

    def set_dependencies(self):
        """Parses all components constructing a dependency tree.

        :raises exception.UnmetDependencyException: If a component has an unmet dependency
        :return: None
        """
        unmet_deps = False

        provides = {}
        requires = {}
        optional = {}

        for group in self.config['groups']:
            for comp in group['components']:
                self.nodes[comp['id']] = Node(comp)

                # collect provides
                if 'provides' in comp:
                    if comp.get('provides'):
                        for entry in comp.get('provides'):
                            if provides.get(entry):
                                provides[entry].append(comp['id'])
                            else:
                                provides[entry] = [comp['id']]
                        if 'noauto' in comp:
                            self.logger.warn(
                                '%s is a "noauto" component and a provider for "%s", this is considered bad practice. '
                                'noauto components should not have depending components!'
                                % (comp['id'], entry))
                    else:
                        self.logger.warn("%s has an empty provides list!" % comp['id'])

                # collect requires
                if 'requires' in comp:
                    if comp.get('requires'):
                        for entry in comp.get('requires'):
                            if requires.get(entry):
                                requires[entry].append(comp['id'])
                            else:
                                requires[entry] = [comp['id']]
                    else:
                        self.logger.warn("%s has an empty requires list!" % comp['id'])

                if 'optional-requires' in comp:
                    if comp.get('optional-requires'):
                        for entry in comp.get('optional-requires'):
                            if optional.get(entry):
                                optional[entry].append(comp['id'])
                            else:
                                optional[entry] = [comp['id']]
                    else:
                        self.logger.warn("%s has an empty optional requires list!" % comp['id'])

        met_optionals = [k for k in optional if k in provides]
        unmet = [k for k in requires if k not in provides]

        if len(unmet) > 0:
            self.logger.critical("Unmet requirements were detected! %s" % unmet)
            single_char = 0

            for deps in unmet:
                if len(unmet):
                    single_char += 1
                    if single_char > 1:
                        self.logger.critical("Detected unmet dependencies with single char ids. Check that requirement "
                                             "definitions in your config are in list-form, even if it is only a single "
                                             "component.")
                        break
            unmet_deps = True

        if len(optional) > 0:
            self.logger.debug("Detected the following optional requirements available: %s" % met_optionals)

            for entry in met_optionals:
                if requires.get(entry):
                    requires[entry].extend(optional[entry])
                else:
                    requires[entry] = optional[entry]

        # Add a pseudo node that depends on all other nodes, to get a starting point to be able to iterate through all
        # nodes with simple algorithms
        master_node = Node({'id': 'master_node'})

        for requirement in requires:
            for requiring_comp in requires.get(requirement):
                if provides.get(requirement):
                    for provider in provides.get(requirement):
                        self.nodes.get(requiring_comp).add_edge(self.nodes.get(provider))

        for id in self.nodes:
            node = self.nodes.get(id)

            if id == 'master_node':
                continue

            # Add edges from each node to pseudo node
            master_node.add_edge(node)

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
            raise exceptions.CircularReferenceException(ex.node1, ex.node2)
        if unmet_deps:
            raise exceptions.UnmetDependenciesException(unmet)

    def _copy_config_to_remote(self, host):
        """Copy the configuration to a remote machine.

        :param host: Host to copy to
        :type host: str
        :return: None
        """
        self.logger.debug("Dumping config to tmp")
        tmp_conf_path = ('%s/%s.yaml' % (config.TMP_CONF_DIR, self.config['name']))
        ensure_dir(tmp_conf_path)

        with open(tmp_conf_path, 'w') as outfile:
            clone = self.config.copy()
            if self.custom_env_path:
                clone['env'] = "%s/%s" % (config.TMP_ENV_PATH, os.path.basename(self.custom_env_path))

            dump(clone, outfile, default_flow_style=False)

            self.logger.debug('Copying config to remote host "%s"' % host)
            cmd = ("ssh -F %s %s 'mkdir -p %s' && scp %s %s:%s/%s.yaml" %
                   (config.CUSTOM_SSH_CONFIG_PATH, host, config.TMP_SLAVE_DIR, tmp_conf_path, host,
                    config.TMP_SLAVE_DIR, self.config['name']))
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

    def add_subscriber(self, subscriber_queue):
        """Add a queue to the list of subscribers for manager and monitoring thread events.

        :param subscriber_queue: Event queue of the subscriber
        :type subscriber_queue: queue.Queue
        :return: None
        """
        self.subscribers.append(subscriber_queue)
        self.mon_thread.add_subscriber(subscriber_queue)
        self.stat_thread.add_subscriber(subscriber_queue)

    def remove_subscriber(self, subscriber_queue):
        """Remove a queue from the list of subscribers for manager and monitoring thread events.

        :param subscriber_queue: Event queue of the subscriber
        :type subscriber_queue: queue.Queue
        :return: None
        """
        self.subscribers.remove(subscriber_queue)
        self.mon_thread.remove_subscriber(subscriber_queue)
        self.stat_thread.remove_subscriber(subscriber_queue)

    ###################
    # Stop
    ###################
    def _stop_remote_component(self, comp):
        """Stops remote component `comp`.

        :param comp: Component to stop
        :type comp: dict
        :return: None
        """
        comp_id = comp['id']
        host = comp['host']

        self.logger.debug("Stopping remote component '%s'" % comp_id)
        if self.host_list.get(comp['host']) is not None:
            if self.slave_server:
                try:
                    self.logger.debug("Issuing stop command to slave server")
                    self.slave_server.stop_component(comp_id, host)
                except exceptions.SlaveNotReachableException as ex:
                    self.logger.debug(ex.message)
            else:
                self.logger.error(
                    "Host %s is reachable but slave is not - hyperion seems not to be installed" % comp['host'])
                self.broadcast_event(events.CheckEvent(comp['id'], config.CheckState.NOT_INSTALLED))
        else:
            self.logger.error(
                "Host %s is unreachable. Can not stop component %s!" % (comp['host'],
                                                                         comp['id']))
            self.broadcast_event(events.CheckEvent(comp['id'], config.CheckState.UNREACHABLE))

    ###################
    # Start
    ###################
    def start_component(self, comp, force_mode=False):
        """Invoke dependency based start of component `comp`.

        Traverses the path of dependencies and invokes a call to ``start_component_without_deps`` for all found
        dependencies before calling it for `comp`.

        :param comp: Component to start
        :type comp: dict
        :param force_mode: Whether starting the main component is tried, even if a dependency failed.
        :type force_mode: bool
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
                if len(failed_comps) == 0 or force_mode:
                    self.logger.debug("Checking and starting %s" % node.comp_id)
                    state = self.check_component(node.component, False)

                    if (state is config.CheckState.STOPPED_BUT_SUCCESSFUL or
                            state is config.CheckState.STARTED_BY_HAND or
                            state is config.CheckState.RUNNING):
                        self.logger.debug("Component '%s' is already running, skipping to next in line" % comp['id'])
                        self.broadcast_event(events.CheckEvent(node.comp_id, state))
                    else:
                        self.logger.debug("Start component '%s' as dependency of '%s'" % (node.comp_id, comp['id']))
                        self.start_component_without_deps(node.component)

                        # Wait component time for startup
                        end_t = time() + get_component_wait(node.component)

                        tries = 0
                        while True:
                            self.logger.debug("Checking %s resulted in checkstate %s" % (node.comp_id,
                                                                                         config.STATE_DESCRIPTION.get(state)))
                            state = self.check_component(node.component, False)
                            if (state is config.CheckState.RUNNING or
                                    state is config.CheckState.STOPPED_BUT_SUCCESSFUL or
                                    state is config.CheckState.STARTED_BY_HAND):
                                self.logger.debug("Dep '%s' success" % node.comp_id)
                                break
                            if tries > 3:
                                self.broadcast_event(events.CheckEvent(comp['id'], config.CheckState.DEP_FAILED))
                                failed_comps[node.comp_id] = state
                                failed_comps[comp['id']] = config.CheckState.DEP_FAILED
                                break
                            if time() > end_t:
                                tries = tries + 1
                            sleep(.5)
                        self.broadcast_event(events.CheckEvent(node.comp_id, state))
                else:
                    self.logger.debug("Previous dependency failed. Only checking '%s' now" % node.comp_id)
                    state = self.check_component(node.component, True)
                    if not (state is config.CheckState.RUNNING or
                            state is config.CheckState.STOPPED_BUT_SUCCESSFUL or
                            state is config.CheckState.STARTED_BY_HAND):
                        failed_comps[node.comp_id] = config.CheckState.DEP_FAILED

        state = self.check_component(node.component, False)
        if (state is config.CheckState.STARTED_BY_HAND or
                state is config.CheckState.RUNNING):
            self.logger.warn("Component %s is already running. Skipping start" % comp['id'])
            self.broadcast_event(events.CheckEvent(comp['id'], state))
            return config.StartState.ALREADY_RUNNING
        else:
            if len(failed_comps) > 0 and not force_mode:
                self.logger.warn("At least one dependency failed and the component is not running. Aborting start")
                failed_comps[comp['id']] = config.CheckState.DEP_FAILED
                self.broadcast_event(events.CheckEvent(comp['id'], state))
                self.broadcast_event(events.StartReportEvent(comp['id'], failed_comps))
                return config.StartState.FAILED
            else:
                self.logger.info(
                    "All dependencies satisfied or force mode is active (%s), starting '%s'" % (force_mode, comp['id'])
                )
                self.start_component_without_deps(comp)

                end_t = time() + get_component_wait(comp)

                tries = 0
                while True:
                    ret = self.check_component(comp, False)

                    if (ret is config.CheckState.RUNNING or
                            ret is config.CheckState.STOPPED_BUT_SUCCESSFUL):
                        break
                    if tries > 3:
                        break
                    if time() > end_t:
                        tries = tries + 1
                    sleep(.5)

            self.broadcast_event(events.CheckEvent(comp['id'], ret))

            if (ret is not config.CheckState.RUNNING and
                    ret is not config.CheckState.STOPPED_BUT_SUCCESSFUL):
                self.logger.warn("All dependencies satisfied, but start failed: %s!" % config.STATE_DESCRIPTION.get(ret))
                self.broadcast_event(events.StartReportEvent(comp['id'], {comp['id']: ret}))
                return config.StartState.FAILED
            return config.StartState.STARTED

    def _start_remote_component(self, comp):
        """Issue start component 'comp' to slave manager on remote host.

        :param comp: Component to start
        :type comp: dict
        :return: None
        """
        comp_id = comp['id']
        host = comp['host']

        self.logger.debug("Starting remote component '%s'" % comp_id)
        if self.host_list.get(comp['host']) is not None:
            if self.slave_server:
                try:
                    self.logger.debug("Issuing start command to slave server")
                    self.slave_server.start_component(comp_id, host)
                except exceptions.SlaveNotReachableException as ex:
                    self.logger.debug(ex.message)
            else:
                self.logger.error(
                    "Host %s is reachable but slave is not - hyperion seems not to be installed" % comp['host'])
                self.broadcast_event(events.CheckEvent(comp['id'], config.CheckState.NOT_INSTALLED))
        else:
            self.logger.error(
                "Host %s is unreachable. Can not start component %s!" % (comp['host'],
                                                                                 comp['id']))
            self.broadcast_event(events.CheckEvent(comp['id'], config.CheckState.UNREACHABLE))

    def start_all(self, force_mode=False):
        """Start all components ordered by dependency.

        If force mode is active, each component start is attempted. If not, after a component failed, each component is
        only checked.

        :param force_mode: Whether to enforce start attempt even if a dependency failed
        :type force_mode: bool
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

            if not failed or force_mode:
                logger.debug("Checking %s" % comp.comp_id)
                ret = self.check_component(comp.component, False)
                if ret is config.CheckState.RUNNING or ret is config.CheckState.STARTED_BY_HAND:
                    logger.debug("Dep %s already running" % comp.comp_id)
                    self.broadcast_event(events.CheckEvent(comp.comp_id, ret))
                else:
                    logger.debug("Starting dep %s" % comp.comp_id)
                    self.start_component_without_deps(comp.component)
                    # Component wait time for startup
                    end_t = time() + get_component_wait(comp.component)

                    tries = 0
                    while True:
                        sleep(.5)
                        ret = self.check_component(comp.component, False)
                        if (ret is config.CheckState.RUNNING or
                                ret is config.CheckState.STOPPED_BUT_SUCCESSFUL):
                            break
                        if tries > 3 or ret is config.CheckState.NOT_INSTALLED or ret is \
                                config.CheckState.UNREACHABLE:
                            logger.debug("Component %s failed, adding it to failed list" % comp.comp_id)
                            failed_comps[comp.comp_id] = ret
                            break
                        if time() > end_t:
                            tries = tries + 1
                    self.broadcast_event(events.CheckEvent(comp.comp_id, ret))
            else:
                ret = self.check_component(comp.component)
                if ret is config.CheckState.STOPPED:
                    self.broadcast_event(events.CheckEvent(comp.comp_id, config.CheckState.DEP_FAILED))
                    failed_comps[comp.comp_id] = config.CheckState.DEP_FAILED
                self.broadcast_event(events.CheckEvent(comp.comp_id, ret))
        self.broadcast_event(events.StartReportEvent('All components', failed_comps))

    def stop_all(self):
        """Stop all components ordered by dependency and run checks afterwards

        :return: None
        """
        try:
            comps = self.get_start_all_list(exclude_no_auto=False)
        except exceptions.CircularReferenceException:
            # If circular dependency is given no components can be started and this is happening in cleanup, so we
            # can safely return without action.
            return

        comps = list(reversed(comps))

        for comp in comps:
            self.stop_component(comp.component)

        for comp in comps:
            self.check_component(comp.component)

    ###################
    # Check
    ###################
    def _check_remote_component(self, comp):
        """Forwards component check to slave manager.

        :param comp: Component to check
        :type comp: dict
        :return: State of the component
        :rtype: config.CheckState
        """
        self.logger.debug("Starting remote check")
        if self.host_list.get(comp['host']) is not None:
            self.logger.debug("Remote '%s' is connected" % comp['host'])
            if self.slave_server:
                self.logger.debug("Slave server is running")
                try:
                    self.logger.debug("Issuing command to slave server")
                    ret_val = self.slave_server.check_component(comp['id'], comp['host'], get_component_wait(comp))
                    self.logger.debug("Slave responded %s" % ret_val)
                except exceptions.SlaveNotReachableException as ex:
                    self.logger.debug(ex.message)
                    ret_val = config.CheckState.NOT_INSTALLED
            else:
                ret_val = config.CheckState.UNREACHABLE

        else:
            self.logger.error(
                "Host %s is unreachable. Can not run check for component %s!" % (comp['host'],
                                                                                 comp['id']))
            ret_val = config.CheckState.UNREACHABLE

        # Create queue event for external notification and return for inner purpose
        self.broadcast_event(events.CheckEvent(comp['id'], ret_val))
        return ret_val

    ###################
    # CLI Functions
    ###################
    def list_components(self):
        """List all components used by the current configuration.

        :return: List of components
        :rtype: list of str
        """

        return [self.nodes.get(node).comp_id for node in self.nodes]

    def start_by_cli(self, comp_id, force_mode=False):
        """Interface function for starting component by name `comp_id` from the cli.

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
        ret = self.start_component(comp, force_mode)
        if ret is config.StartState.STARTED:
            logger.info("Started component '%s'" % comp_id)
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
            cmd = "ssh -tt -F %s %s 'bash -s' < %s" % (config.CUSTOM_SSH_CONFIG_PATH, hostname, remote_cmd)
            call(cmd, shell=True)

    def show_comp_log(self, comp_id):
        """Interface function for viewing the log of component by name `comp_id` from the cli.

        :param comp_id: Id of the component whose log to show (name@host)
        :type comp_id: str
        :return: None
        """
        host = comp_id.split('@')[1]
        cmd = '/bin/bash -c "tail -n +1 -F %s/localhost/component/%s/latest.log"' % (config.TMP_LOG_PATH, comp_id)

        comp = self.get_component_by_id(comp_id)

        try:
            on_localhost = self.run_on_localhost(comp)
        except exceptions.HostUnknownException:
            self.logger.warn("Host '%s' is unknown and therefore not reachable!" % host)
            return

        if on_localhost:
            try:
                call(cmd, shell=True)
            except KeyboardInterrupt:
                pass
        else:
            cmd = '/bin/bash -c "tail -n +1 -F %s/localhost/component/%s/latest.log"' % (config.TMP_LOG_PATH, comp_id)
            try:
                call("ssh -F %s %s '%s'" % (config.CUSTOM_SSH_CONFIG_PATH, host, cmd),
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

        it = list(res)
        [res.remove(entry) if 'noauto' in entry.component else '' for entry in it]

        return res

    def get_start_all_list(self, exclude_no_auto=True):
        """Get a list of all components ordered by dependency (from dependency to depends on).

        :return: List of components
        :rtype: list of Node
        """

        node = self.nodes.get('master_node')

        if node is None:
            return []

        res = []
        unres = []
        dep_resolve(node, res, unres)
        res.remove(node)

        it = list(res)
        if exclude_no_auto:
            [res.remove(entry) if 'noauto' in entry.component else '' for entry in it]

        return res

    ###################
    # SSH stuff
    ###################
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
            self.host_states[hostname] = config.HostState.DISCONNECTED
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
        t_min = time() + 0.5

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
            if len(pids) > 0 and time() > t_min:
                break

        if len(pids) < 1:
            self.host_list_lock.acquire()
            self.host_list[hostname] = None
            self.host_states[hostname] = config.HostState.DISCONNECTED
            self.host_stats[hostname] = ['N/A', 'N/A', 'N/A']
            self.host_list_lock.release()
            return False

        try:
            ssh_proc = Process(pids[0])
        except NoSuchProcess:
            self.logger.debug("ssh process is long gone already. Connection failed")
            self.logger.error("SSH connection was not successful. Make sure that an ssh connection is allowed, "
                              "you have set up ssh-keys and the identification certificate is up to date")
            self.host_list_lock.acquire()
            self.host_list[hostname] = None
            self.host_states[hostname] = config.HostState.DISCONNECTED
            self.host_stats[hostname] = ['N/A', 'N/A', 'N/A']
            self.host_list_lock.release()
            return False

        # Add host to known list with process to poll from
        self.host_list_lock.acquire()
        self.host_list[hostname] = ssh_proc
        self.host_states[hostname] = config.HostState.SSH_ONLY
        self.host_list_lock.release()

        self.logger.debug("Testing if connection was successful")
        if ssh_proc.is_running():
            self.logger.debug("SSH process still running. Connection was successful")
            self.logger.debug("Adding ssh master to monitor queue")
            self.monitor_queue.put(HostMonitorJob(pids[0], hostname, self.host_list, self.host_list_lock))
            self.logger.debug("Copying env files to remote %s" % hostname)
            self._copy_env_file(hostname)
            self._copy_config_to_remote(hostname)
            return True
        else:
            self.logger.error("SSH connection was not successful. Make sure that an ssh connection is allowed, "
                              "you have set up ssh-keys and the identification certificate is up to date")
            self.host_list_lock.acquire()
            self.host_list[hostname] = None
            self.host_states[hostname] = config.HostState.DISCONNECTED
            self.host_stats[hostname] = ['N/A', 'N/A', 'N/A']
            self.host_list_lock.release()
            return False

    def reconnect_with_host(self, hostname):
        """Re-establish master connection to host `hostname`

        :param hostname: Host to connect to
        :type hostname: str
        :return: Whether establishing the connection was successful or not
        :rtype: bool
        """
        old_status = self.host_states.get(hostname)

        # Check if really necessary
        self.logger.debug("Reconnecting with %s" % hostname)
        proc = self.host_list.get(hostname)
        if proc is not None and not proc.is_running():
            self.logger.debug("Killing off leftover process")
            proc.kill()

        # Start new connection
        if self._establish_master_connection(hostname):
            if old_status is config.HostState.DISCONNECTED:
                self.broadcast_event(events.ReconnectEvent(hostname))
            self._start_remote_slave(hostname)
            return True
        else:
            return False

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

    def cleanup(self, full=False, status=config.ExitStatus.FINE):
        """Clean up for safe shutdown.

        Kills the monitoring thread and if full shutdown is requested also the ssh slave sessions and master connections
        and then shuts down the local tmux master session.

        :param full: Whether everything shall be shutdown or not
        :type full: bool
        :param status: Status context this function was invoked from. The application will exit with that status
        :type status: config.ExitStatus
        :return: None
        """
        self.logger.info("Shutting down safely...")

        self.logger.debug("Killing monitoring thread")
        self.mon_thread.kill()
        self.stat_thread.kill()

        if full:
            self.logger.debug("Stopping all components")
            self.stop_all()

        if self.slave_server:
            self.slave_server.kill_slaves(full)
            self.slave_server.stop()

        if full:
            self.logger.info("Chose full shutdown. Killing remote and main sessions")

            for host in self.host_list:
                window = self._find_window('ssh-%s' % host)

                if window:
                    self.logger.debug("Killing remote slave session of host %s" % host)
                    self.kill_remote_session_by_name("slave-session", host)
                    self.logger.debug("Closing ssh-master window of host %s" % host)
                    self._kill_window(window)

            self.kill_session_by_name(self.session_name)

        self.logger.info("... Done")
        exit(status)

    def start_remote_clone_session(self, comp):
        """Start a clone session of the remote slave session and open the window of component `comp`.

        :param comp: Component whose window is to be shown in the clone session
        :type comp: dict
        :return:
        """
        comp_id = comp['id']
        host = comp['host']

        self.logger.debug("Starting remote clone session for component '%s'" % comp_id)
        if self.host_list.get(comp['host']) is not None:
            if self.slave_server:
                try:
                    self.logger.debug("Issuing start command to slave server")
                    self.slave_server.start_clone_session(comp_id, host)
                except exceptions.SlaveNotReachableException as ex:
                    self.logger.debug(ex.message)
            else:
                self.logger.error(
                    "Host %s is reachable but slave is not - hyperion seems not to be installed" % comp['host'])
        else:
            self.logger.error(
                "Host %s is unreachable. Can not start remote clone session for component %s!" % (comp['host'],
                                                                                                  comp['id']))


class SlaveManager(AbstractController):
    """Controller class that manages components on a slave machine."""

    def start_remote_clone_session(self, comp):
        self.logger.error("This function is disabled for slave managers!")
        pass

    def _stop_remote_component(self, comp):
        self.logger.error("This function is disabled for slave managers!")
        pass

    def _start_remote_component(self, comp):
        self.logger.error("This function is disabled for slave managers!")
        pass

    def _check_remote_component(self, comp):
        self.logger.error("This function is disabled for slave managers!")
        pass

    def start_all(self, force_mode=False):
        self.logger.error("This function is disabled for slave managers!")
        pass

    def start_local_clone_session(self, comp):
        session_name = '%s-slave' % self.config['name']
        comp_id = comp['id']

        cmd = "%s '%s' '%s'" % (SCRIPT_CLONE_PATH, session_name, comp_id)
        call(cmd, shell=True)

    def reload_config(self):

        old_conf = self.config.copy

        try:
            self._load_config(self.configfile)
        except exceptions.MissingComponentDefinitionException as err:
            self.logger.error("Included file '%s' not found!" % err.filename)
            self.logger.error("Reloading config failed - falling back to old config!")
            self.config = old_conf
        except IOError:
            self.logger.error("Reloading config failed - falling back to old config!")
            self.config = old_conf
        except exceptions.EnvNotFoundException:
            self.logger.error("Reloading config failed: Env file not found - falling back to old config!")
        self.session_name = '%s-slave' % self.config["name"]

        self.logger.info("Config reload was successful")

    def start_component(self, comp, force_mode=True):
        """Start component on a slave.

        This function just calls `start_component_without_deps` because dependencies are managed by the master server.

        :param comp: Component to start
        :type comp: dict
        :param force_mode: Whether start is forced or not. (Slave always starts without dependency resolution thus this
        parameter does not affect this subclass implementation)
        :type force_mode: bool
        :return: None
        """
        # Is equivalent to start_without_deps because
        self.start_component_without_deps(comp)

    def stop_all(self):
        self.logger.error("This function is disabled for slave managers!")
        pass

    def reconnect_with_host(self, hostname):
        self.logger.error("This function is disabled for slave managers!")
        pass

    def __init__(self, configfile):
        """Initialize slave manager.

        :param configfile: Path to configuration file.
        :type configfile: str
        """
        super(SlaveManager, self).__init__(configfile)
        self.nodes = {}
        self.host_list = {
            '%s' % socket.gethostname(): True
        }
        self.monitor_queue = queue.Queue()
        self.mon_thread = ComponentMonitor(self.monitor_queue)
        self.mon_thread.start()

        if configfile:
            try:
                self._load_config(configfile)
            except (IOError, exceptions.MissingComponentDefinitionException):
                self.cleanup(exit_status=config.ExitStatus.CONFIG_PARSING_ERROR)
            except exceptions.EnvNotFoundException:
                self.cleanup(exit_status=config.ExitStatus.ENVIRONMENT_FILE_MISSING)
            self.session_name = '%s-slave' % self.config["name"]

            self.logger.info("Loading config was successful")

            self.server = Server()

            session_ready = False
            try:
                if self.server.has_session(self.session_name):
                    self.session = self.server.find_where({
                        "session_name": self.session_name
                    })

                    self.logger.info('found running session by name "%s" on server' % self.session_name)
                    session_ready=True
            except LibTmuxException:
                self.logger.debug("Exception in libtmux while looking up sessions. Maybe no session is running. Trying "
                                  "to create a new one")
            if not session_ready:
                self.logger.info('starting new session by name "%s" on server' % self.session_name)
                self.session = self.server.new_session(
                    session_name=self.session_name,
                    window_name="Main"
                )

        else:
            self.config = None

    def cleanup(self, full=False, exit_status=config.ExitStatus.FINE):
        """Clean up for safe shutdown.

        Kills the monitoring thread and if full shutdown is requested also the ssh slave sessions and master connections
        and then shuts down the local tmux master session.

        :param full: Whether everything shall be shutdown or not
        :type full: bool
        :param exit_status: Status context this function was invoked from. The application will exit with that status
        :type exit_status: config.ExitStatus
        :return: None
        """
        self.logger.info("Shutting down safely...")

        self.logger.debug("Killing monitoring thread")
        self.mon_thread.kill()
        self.stat_thread.kill()

        if full:
            self.logger.info("Chose full shutdown. Killing tmux sessions")
            self.kill_session_by_name(self.session_name)

        self.logger.info("... Done")
        exit(exit_status)

    def add_subscriber(self, subscriber):
        """Add a queue to the list of subscribers for manager and monitoring thread events.

        :param subscriber: Event queue of the subscriber
        :type subscriber: queue.Queue
        :return: None
        """
        self.subscribers.append(subscriber)
        self.mon_thread.add_subscriber(subscriber)
        self.stat_thread.add_subscriber(subscriber)
