#! /usr/bin/env python
from libtmux.exc import LibTmuxException
from libtmux import Server, Session, Window
from yaml import load, dump
import re
import logging
import os
import socket
import shutil
from psutil import Process, NoSuchProcess
from subprocess import call, Popen, PIPE, STDOUT
from threading import Lock
from time import sleep, time, strftime
from hyperion.lib.util.setupParser import Loader
from hyperion.lib.util.depTree import Node, dep_resolve, resolve_concurrent_start
from hyperion.lib.monitoring.threads import (
    StatMonitor,
    ComponentMonitor,
    CancellationJob,
    HostMonitorJob,
    LocalComponentMonitoringJob,
    RemoteComponentMonitoringJob,
)
import hyperion.lib.util.exception as exceptions
import hyperion.lib.util.config as config
import hyperion.lib.util.events as events
import hyperion.lib.util.actionSerializer as actionSerializer

from collections import deque
from multiprocessing.pool import AsyncResult, ThreadPool

import queue as queue

from typing import Optional, Tuple, Any, NoReturn, Union
from hyperion.lib.util.types import Component, Config

BASE_DIR = os.path.dirname(__file__)
"""Path to the directory this file is contained in"""

SCRIPT_CLONE_PATH = f"{BASE_DIR}/bin/start_named_clone_session.sh"
"""File path of the 'clone session' script"""

SCRIPT_SHOW_SESSION_PATH = f"{BASE_DIR}/bin/show_session.sh"
"""File path of the 'clone session' script"""


###################
# Logging
###################
def setup_log(
    window: Window, filepath: str, comp_id: str, start_logging: bool = True
) -> None:
    """Redirect stdout and stderr of window to file.

    Rotate logs and ensure the log directory for a component with id `comp_id` exists, than,
    redirect the outputs of `window` to /dev/tty to undo the case that previous output was already redirected.
    After that redirect outputs to `file`.

    Parameters
    ----------
    window : Window
        tmux reference to the window the component is being run in.
    filepath : str
        Filepath of the component log file.
    comp_id : str
        Id of the component being run (name@host).
    start_logging : bool, optional
        Whether pipeing the content of `Window` should be set up (only necessary once after Window is created), by default True
    """
    ensure_dir(filepath, mask=config.DEFAULT_LOG_UMASK)
    rotate_log(filepath, comp_id)

    if start_logging:
        logging.debug(f"Started logging for component '{comp_id}'")
        # Reroute stdout and stderr to log file
        window.cmd("pipe-pane", f"exec cat >> {filepath}")
    window.cmd(
        "send-keys", (f'echo "#Hyperion component start: {comp_id}\\t$(date)"'), "Enter"
    )


def get_component_wait(comp: Component) -> float:
    """Returns time to wait after component start (default of 3 seconds unless overwritten in configuration).

    Parameters
    ----------
    comp : Component
        Component configuration.

    Returns
    -------
    float
        Configured wait time in seconds.
    """

    logger = logging.getLogger(__name__)
    logger.debug(f"Retrieving wait time of component {comp['name']}")
    if "wait" in comp:
        logger.debug(
            f"Found {float(comp['wait'])} seconds as wait time for {comp['name']}"
        )
        return float(comp["wait"])
    else:
        logger.debug(
            f"No wait time for {comp['name']} found, using default of {config.DEFAULT_COMP_WAIT_TIME} seconds"
        )
        return config.DEFAULT_COMP_WAIT_TIME


def rotate_log(file_path: str, log_name: str) -> None:
    """If found rename the log at file_path to e.g. COMPONENTNAME_TIME.log or 'server_TIME.log'.

    Parameters
    ----------
    file_path : str
        Log file path.
    log_name : str
        Name prefix of the log (current time will be appended).
    """

    if os.path.isfile(file_path):
        # set new umask, remembering old one
        old_mask = os.umask(config.DEFAULT_LOG_UMASK)
        directory = os.path.dirname(file_path)
        os.rename(file_path, f"{directory}/{log_name}_{strftime('%H-%M-%S')}.log")
    
        # reset previous umask
        os.umask(old_mask)


def ensure_dir(file_path: str, mask: int = 0o777) -> None:
    """If not already existing, recursively create parent directory of `file_path`.

    Parameters
    ----------
    file_path : str
        Log file path.
    mask : int, optional
        Umask to create directories with, by default 0o777
    """

    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        prev_mask = os.umask(mask)
        os.makedirs(directory)
        os.umask(prev_mask)


def dump_config(conf: dict) -> None:
    """Dumps configuration in a file called conf-result.yaml.

    Parameters
    ----------
    conf : dict
        Configuration to dump.
    """

    with open("conf-result.yml", "w") as outfile:
        dump(conf, outfile, default_flow_style=False)


def conf_preprocessing(
    conf: Config, custom_env: Optional[str] = None, exclude_tags: Optional[list[str]] = None
) -> None:
    """Preprocess configuration file.

    Comprises a) setting all component ids to comp_name@host and b) interpreting environment variables in hostnames.

    Parameters
    ----------
    conf : Config
        Config to preprocess
    custom_env : str, optional
        Path to custom environment to source before trying to evaluate env variables, by default None.
    exclude_tags : list[str], optional
        List of tags to exclude marked components from the config, by default None.

    Raises
    ------
    exceptions.DuplicateGroupDefinitionException
        If a duplicate group was found in `conf`.
    """

    if custom_env:
        pipe = Popen(
            f". {custom_env} > /dev/null; env",
            stdout=PIPE,
            stderr=PIPE,
            shell=True,
            executable=config.SHELL_EXECUTABLE_PATH,
        )
        data, err_lines_raw = pipe.communicate()

        if err_lines_raw and len(err_lines_raw) > 0:
            err_lines = err_lines_raw.decode("utf-8")
            logging.getLogger(__name__).critical(
                "Sourcing the custom environment file of this config returned with an error! "
                f"Is it suitable for the selected shell executable ('{config.SHELL_EXECUTABLE_PATH}')? "
                f"Full stderr output:\n{err_lines}"
            )

        keys = []
        values = []
        for line in data.splitlines():
            entry = line.decode("utf-8").split("=", 1)

            if len(entry) == 2:
                keys.append(entry[0])
                values.append(entry[1])
            else:
                logging.debug(f"Line in env omitted: {line.decode('utf-8')}")
        os.environ.update(dict(zip(keys, values)))

    pattern = "\\${(.*)}"
    pattern2 = ".*@\\${(.*)}"
    logging.debug(f"Pattern {pattern}")

    duplicate_check_list = []
    for group in conf["groups"]:
        if group["name"] in duplicate_check_list:
            raise exceptions.DuplicateGroupDefinitionException(group["name"])
        duplicate_check_list.append(group["name"])

        exclude_from_group = []
        for comp in group["components"]:
            if exclude_tags and comp.get("tags") is not None:
                for tag in comp["tags"]:
                    if tag in exclude_tags:
                        logging.getLogger(__name__).debug(
                            f"Exclude component {comp['name']} because of tag: {tag}"
                        )
                        exclude_from_group.append(comp)
                        break

            host = comp["host"]
            match = re.compile(pattern).match(host)

            if match and len(match.groups()) > 0:
                hn = os.environ.get(match.groups()[0])
                if not hn:
                    hn = match.groups()[0]
                comp["host"] = hn

            comp["id"] = f"{comp['name']}@{comp['host']}"

            if "depends" in comp:
                dep_index = 0
                for dep in comp["depends"]:
                    match = re.compile(pattern2).match(dep)

                    if match and len(match.groups()) > 0:
                        host_var = os.environ.get(match.groups()[0])
                        if not host_var:
                            host_var = match.groups()[0]
                        comp["depends"][dep_index] = re.sub(pattern, host_var, dep)
                    dep_index += 1

        if len(exclude_from_group) > 0:
            c_list = group["components"]
            [c_list.remove(comp) for comp in exclude_from_group] # type: ignore[func-returns-value]
            group["components"] = c_list


def get_component_cmd(component: Component, cmd_type: str) -> Optional[str]:
    """Retrieve component cmd from config.

    Parameters
    ----------
    component : dict
        Compnent configuration.
    cmd_type : str
        Type of the cmd. Valid types are `start`, `check` and `stop`

    Returns
    -------
    Optional[str]
        Command as string or None
    """

    if cmd_type != "start" and cmd_type != "check" and cmd_type != "stop":
        logging.getLogger(__name__).error(
            f"Unrecognized cmd type '{cmd_type}' was given"
        )
        return None

    cmd = None
    for ind, found in enumerate(
        [True if cmd_type in cmd_tmp else "" for cmd_tmp in component["cmd"]]
    ):
        if found:
            cmd = component["cmd"][ind][cmd_type]
    return cmd


####################
# SSH Stuff
####################
def setup_ssh_config() -> bool:
    """Creates an ssh configuration that is saved to `CUSTOM_SSH_CONFIG_PATH`.

    The user config in `SSH_CONFIG_PATH` is copied to `CUSTOM_SSH_CONFIG_PATH` and then appends the lines enabling
    master connections for all hosts to it. This is done in order to use the master connection feature without
    tempering with the users standard configuration.

    Returns
    -------
    bool
        Whether copying was successful or not.
    """

    logger = logging.getLogger(__name__)
    try:
        logger.debug(
            f"Trying to copy ssh config from {config.SSH_CONFIG_PATH} to {config.CUSTOM_SSH_CONFIG_PATH}"
        )
        ensure_dir(config.CUSTOM_SSH_CONFIG_PATH, mask=config.DEFAULT_LOG_UMASK)
        ensure_dir(
            f"{config.SSH_CONTROLMASTERS_PATH}/somefile", mask=config.DEFAULT_LOG_UMASK
        )
        shutil.copy(config.SSH_CONFIG_PATH, config.CUSTOM_SSH_CONFIG_PATH)
    except IOError:
        logger.warn("Could not copy ssh config! Creating config from scratch!")
        if os.path.isfile(config.CUSTOM_SSH_CONFIG_PATH):
            os.remove(config.CUSTOM_SSH_CONFIG_PATH)
        os.mknod(config.CUSTOM_SSH_CONFIG_PATH)

    try:
        conf = open(config.CUSTOM_SSH_CONFIG_PATH, "a")
        conf.write(
            "\n"
            "Host *\n"
            "    ControlMaster no\n"
            "    ControlPath ~/.ssh/controlmasters/%r@%h:%p\n"
            "    ServerAliveInterval 10\n"
            "    PasswordAuthentication no"
        )
    except IOError:
        logger.error("Could not append to custom ssh config!")
        return False

    return True

def resolve_host_address(hostname: str, ssh_config_path: str) -> Union[str, None]:
    """Checks several methods to resolve and ip from a hostname.

    Parameters
    ----------
    hostname : str
        Hostname to get the adress to.
    ssh_config_path : str
        Path to ssh config (for possible hostname resolution).

    Returns
    -------
    Union[str,None]
        If host could be reached, returns the correct ip, otherwise None.
    """    

    is_up = (
        True if os.system("ping -w2 -c 1 %s > /dev/null" % hostname) == 0 else False
    )
    if not is_up:
        # Try resolving the host ip or a different name, in case host is known not by /etc/hosts but set through ssh-config
        ip_cmd = "ssh -F %s -G %s | awk '/^hostname / { print $2 }'" % (
            ssh_config_path,
            hostname
        )
        ps = Popen(ip_cmd, shell=True, stdout=PIPE, stderr=STDOUT)
        ip = ps.communicate()[0].decode('utf-8').rstrip()
        is_up = (
            True if os.system("ping -w2 -c 1 %s > /dev/null" % ip) == 0 else False
        )

        if not is_up:
            hn_out = socket.gethostbyname(hostname)
            is_up = (
                True if os.system("ping -w2 -c 1 %s > /dev/null" % hn_out) == 0 else False
            )

            if not is_up:
                return None
            return hn_out
        return ip
    return hostname


class AbstractController(object):
    """Abstract controller class that defines basic controller variables and methods."""

    def __init__(self, configfile: Optional[str]) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(config.DEFAULT_LOG_LEVEL)
        if configfile is not None:
            self.configfile = configfile
        self.monitor_queue = queue.Queue() # type: queue.Queue
        self.custom_env_path: Optional[str] = None
        self.subscribers: list[queue.Queue] = []
        self.stat_thread = StatMonitor()
        self.config: Config = {}
        self.session: Optional[Session] = None
        self.server: Optional[Server] = None
        self.dev_mode = True
        self.exclude_tags: Optional[list[str]] = None
        self.monitor_queue = queue.Queue() # type: queue.Queue
        self.mon_thread = ComponentMonitor(self.monitor_queue)

    def broadcast_event(self, event: events.BaseEvent) -> None:
        """Put a given event in all registered subscriber queues.

        Parameters
        ----------
        event : events.BaseEvent
            Event to broadcast.
        """

        for subscriber in self.subscribers:
            subscriber.put(event)

    def _load_config(self, filename: str = "default.yaml") -> None:
        """Load configuration recursively from yaml file.

        Parameters
        ----------
        filename : str, optional
            Path to the configuration file, by default "default.yaml".

        Raises
        ------
        IOError
            If opening the config file failed.
        exceptions.MissingComponentDefinitionException
            If a nested component or group file could not be found.
        exceptions.EnvNotFoundException
            If the custom environment file could not be found.
        """

        try:
            with open(filename) as data_file:
                self.config = load(data_file, Loader)
        except IOError as e:
            self.logger.critical(f"No config file at '{filename}' found")
            raise e
        except exceptions.MissingComponentDefinitionException as err:
            self.logger.critical(f"File '{err}' included by config not found!")
            raise err

        self.session_name = self.config["name"]

        if self.config.get("env") is not None:
            env = self.config["env"]
            if os.path.isfile(env):
                self.logger.debug("Custom env given as absolute path! Saving to config")
                self.custom_env_path = env
            elif os.path.isfile(os.path.join(os.path.dirname(filename), env)):
                self.logger.debug("Custom env given as relative path! Saving to config")
                self.custom_env_path = os.path.abspath(
                    os.path.join(os.path.dirname(filename), env)
                )
            else:
                self.logger.critical(f"Env file {env} could not be found!")
                raise exceptions.EnvNotFoundException(
                    f"Env file {env} could not be found!"
                )

        if self.config.get("slave_hyperion_source_path") is not None:
            config.SLAVE_HYPERION_SOURCE_PATH = self.config[
                "slave_hyperion_source_path"
            ]
            self.logger.info(
                f"Will source file '{config.SLAVE_HYPERION_SOURCE_PATH}' before starting slave on remote"
            )

        if self.config.get("exclude") is not None:
            self.exclude_tags = self.config["exclude"]
            self.logger.info(
                f"Following tags are excluded by configuration: {self.exclude_tags}"
            )

        if self.config.get("shell_path") is not None:
            config.SHELL_EXECUTABLE_PATH = self.config["shell_path"]
            self.logger.info(
                f"Changed default shell to: '{config.SHELL_EXECUTABLE_PATH}'"
            )

        if self.config.get("monitoring_rate") is not None:
            config.MONITORING_RATE = self.config["monitoring_rate"]
            self.logger.info(
                f"Changed monitoring rate to: '{config.MONITORING_RATE} Hz'"
            )

        if self.config.get("verbose_checks") is not None:
            config.SHOW_CHECK_OUTPUT = self.config["verbose_checks"]
            self.logger.info(f"Set verbose checks to: '{config.SHOW_CHECK_OUTPUT}'")

        if self.config.get("local_monitor") is not None:
            config.MONITOR_LOCAL_STATS = self.config["local_monitor"]
            if not config.MONITOR_LOCAL_STATS:
                self.logger.info("Disabled local stat monitoring")

        if self.config.get("local_stat_rate") is not None:
            config.LOCAL_STAT_MONITOR_RATE = self.config["local_stat_rate"]
            self.logger.info(
                f"Changed local stat monitoring rate to: '{config.LOCAL_STAT_MONITOR_RATE} Hz'"
            )

        if self.config.get("remote_monitor") is not None:
            config.MONITOR_REMOTE_STATS = self.config["remote_monitor"]
            if not config.MONITOR_REMOTE_STATS:
                self.logger.info("Disabled remote stat monitoring")

        if self.config.get("remote_stat_rate") is not None:
            config.REMOTE_STAT_MONITOR_RATE = self.config["remote_stat_rate"]
            self.logger.info(
                f"Changed remote stat monitoring rate to: '{config.REMOTE_STAT_MONITOR_RATE} Hz'"
            )

        if self.config.get("log_umask") is not None:
            config.DEFAULT_LOG_UMASK = int(self.config["log_umask"], 8)
            self.logger.info(
                f"Changed default log umask to '{config.DEFAULT_LOG_UMASK}'"
            )

        self.logger.info(f"Running {config.DEFAULT_THREADN} threads for starting/stopping")

    ###################
    # Component Management
    ###################
    def _run_component_check(self, comp: Component) -> bool:
        """Runs the component check defined in the component configuration and returns the exit state.

        Parameters
        ----------
        comp : Component
            Component configuration.

        Returns
        -------
        bool
            Check exit state (fail = False / success = True).
        """

        self.logger.debug(f"Running specific component check for {comp['name']}")

        shell_init = ""
        if self.custom_env_path:
            shell_init = f". {self.custom_env_path}; "

        check = get_component_cmd(comp, "check")

        p = Popen(
            f"{shell_init}{check}",
            shell=True,
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE,
            executable=config.SHELL_EXECUTABLE_PATH,
        )

        while p.poll() is None:
            sleep(0.5)
        
        if config.SHOW_CHECK_OUTPUT:
            if p.stdout is not None:
                out_raw = p.stdout.readlines()
                out = map(lambda x: x.decode(encoding="UTF-8"), out_raw)
                self.logger.info((f"Check output of '{comp['id']}':\n{''.join(out)}"))

            if p.stderr is not None:
                err_out_list_raw = p.stderr.readlines()
                if len(err_out_list_raw):
                    err_out_list = map(lambda x: x.decode(encoding="UTF-8"), err_out_list_raw)
                    self.logger.error(
                        (f"'{comp['id']}' check stderr:\n{''.join(err_out_list)}")
                    )

        if p.returncode == 0:
            self.logger.debug("Check returned true")
            return True
        else:
            self.logger.debug("Check returned false")
            return False

    def get_component_by_id(self, comp_id: str) -> Component:
        """Return component configuration by providing only the id (name@host).

        Parameters
        ----------
        comp_id : str
            Component id.

        Returns
        -------
        dict
            Component configuration.

        Raises
        ------
        exceptions.ComponentNotFoundException
            If no component with id `comp_id` could be found in the current config.
        """

        self.logger.debug(f"Searching for {comp_id} in components")
        for group in self.config["groups"]:
            for comp in group["components"]:
                if comp["id"] == comp_id:
                    self.logger.debug(f"Component '{comp_id}' found")
                    return comp
        raise exceptions.ComponentNotFoundException(comp_id)

    ###################
    # start
    ###################
    def start_component_without_deps(self, comp: Component) -> None:
        """Chooses which lower level start function to use depending on whether the component is run on a remote host or not.

        Parameters
        ----------
        comp : Component
            Component to start.
        """

        comp_id = comp["id"]
        host = comp["host"]

        self.broadcast_event(events.StartingEvent(comp_id))

        try:
            on_localhost = self.run_on_localhost(comp)
        except exceptions.HostUnknownException:
            self.logger.warn(
                f"Host '{comp['host']}' is unknown and therefore not reachable!"
            )
            return

        if host != "localhost" and not on_localhost:
            self.logger.info(f"Starting remote component '{comp_id}' on host '{host}'")
            self._start_remote_component(comp)
        else:
            log_file = f"{config.TMP_LOG_PATH}/localhost/component/{comp_id}/latest.log"
            window = self._find_window(comp_id)
            self.logger.info(f"Starting local component '{comp['id']}'")

            if window:
                self.logger.debug(f"Restarting '{comp_id}' in old window")
                self._start_window(window, comp, log_file)
            else:
                self.logger.debug(f"creating window '{comp_id}'")
                assert self.session is not None
                window = self.session.new_window(
                    window_name=comp_id, window_shell=config.SHELL_EXECUTABLE_PATH
                )
                self._start_window(window, comp, log_file)

    ###################
    # Stop
    ###################
    def stop_component(self, comp: Component) -> None:
        """Stop component `comp`.

        Invokes the lower level stop function depending on whether the component is run locally or on a remote host.

        Parameters
        ----------
        comp : Component
            Component to stop
        """

        self.broadcast_event(events.StoppingEvent(comp["id"]))

        self.logger.debug(f"Removing {comp['id']} from process monitoring list")
        self.monitor_queue.put(CancellationJob(0, comp["id"]))

        try:
            on_localhost = self.run_on_localhost(comp)
        except exceptions.HostUnknownException:
            self.logger.warn(
                f"Host '{comp['host']}' is unknown and therefore not reachable!"
            )
            return
        if comp["host"] != "localhost" and not on_localhost:
            self.logger.info(f"Stopping remote component '{comp['id']}'")
            self._stop_remote_component(comp)
        else:
            self.logger.info(f"Stopping local component '{comp['id']}'")
            window = self._find_window(comp["id"])

            if window:
                self.logger.debug(f"window '{comp['id']}' found running")
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
                            self.logger.warn(
                                "C-c running for over 10 seconds, "
                                f"killing off process of window {comp['id']}"
                            )

                stop = get_component_cmd(comp, "stop")
                if stop:
                    self.logger.debug("Found custom stop command")
                    window.cmd("send-keys", stop, "Enter")

                    end_t = time() + 2
                    wait = True
                    while wait:
                        if not self._is_window_busy(window):
                            wait = False
                        elif time() < end_t:
                            wait = False
                            self.logger.error(
                                "Stop command still running after 2 seconds... stop waiting for"
                                "termination"
                            )

                self._kill_window(window)

                self.logger.debug("... done!")
            else:
                self.logger.warning(
                    f"Component '{comp['id']}' seems to already be stopped"
                )

    ###################
    # Check
    ###################
    def check_component(self, comp: Component, broadcast: bool = True) -> config.CheckState:
        """Runs component check for `comp` and returns status.

        If `comp` is run locally the call is redirected to ``check_local_component``, if `comp` is run on a remote
        host the call is redirected to ``check_remote_component``.

        Parameters
        ----------
        comp : Component
            Config of component to check.
        broadcast : bool, optional
            Whether to broadcast the result to receivers or not, by default True.

        Returns
        -------
        config.CheckState
            State of the component
        """

        if self.mon_thread.is_component_monitored(comp["id"]):
            if broadcast:
                self.broadcast_event(events.CheckEvent(comp["id"], config.CheckState.RUNNING))
            return config.CheckState.RUNNING

        try:
            on_localhost = self.run_on_localhost(comp)
            if on_localhost:
                ret = self._check_local_component(comp)

                pid = ret[0]
                if pid != 0:
                    self.monitor_queue.put(LocalComponentMonitoringJob(pid, comp["id"]))
                ret_val = ret[1]
            else:
                ret_val = self._check_remote_component(comp)

        except exceptions.HostUnknownException:
            self.logger.warn(
                f"Host '{comp['host']}' is unknown and therefore not reachable!"
            )
            ret_val = config.CheckState.UNREACHABLE
            pass

        # Create queue event for external notification and return for inner purpose
        # But only broadcast if it was a local check or no answer was received, because remote events will be
        # forwarded automatically
        if (ret_val == config.CheckState.UNREACHABLE or on_localhost) and broadcast:
            self.broadcast_event(events.CheckEvent(comp["id"], ret_val))
        return ret_val

    def _check_local_component(self, comp: Component) -> Tuple[int, config.CheckState]:
        """Check if a local component is running and return the corresponding CheckState.

        Parameters
        ----------
        comp : Component
            Component configuration.

        Returns
        -------
        Tuple[int, config.CheckState]
            pid and component status. If the component is not running, the pid is 0.
        """

        logger = self.logger

        logger.debug(f"Running component check for {comp['id']}")
        check_available = get_component_cmd(comp, "check") is not None
        window = self._find_window(comp["id"])

        pid = 0

        if window:
            if not self._is_window_busy(window):
                logger.debug(
                    "Main process has finished. Running custom check if available"
                )
                if check_available and self._run_component_check(comp):
                    logger.debug("Process terminated but check was successful")
                    ret = config.CheckState.STOPPED_BUT_SUCCESSFUL
                else:
                    logger.debug("Check failed or no check available: returning false")
                    ret = config.CheckState.STOPPED
            elif check_available and self._run_component_check(comp):
                logger.debug("Check succeeded")
                ret = config.CheckState.RUNNING
                children = Process(int(window.pane_pid)).children()
                if len(children) > 0:
                    pid = children[0].pid
            elif not check_available:
                logger.debug(
                    "No custom check specified and window is busy: returning true"
                )
                ret = config.CheckState.RUNNING
                children = Process(int(window.pane_pid)).children()
                if len(children) > 0:
                    pid = children[0].pid
            else:
                logger.debug("Check failed: returning false")
                ret = config.CheckState.STOPPED
        else:
            logger.debug(f"{comp['name']} window is not running. Running custom check")
            if check_available and self._run_component_check(comp):
                logger.debug(
                    "Component was not started by Hyperion, but the check succeeded"
                )
                ret = config.CheckState.STARTED_BY_HAND
            else:
                logger.debug(
                    "Window not running and no check command is available or it failed: returning false"
                )
                ret = config.CheckState.STOPPED

        return pid, ret

    ###################
    # Host related checks
    ###################
    def is_localhost(self, hostname: str) -> bool:
        """Check if 'hostname' resolves to localhost.

        Parameters
        ----------
        hostname : str
            Name of host to check.

        Returns
        -------
        bool
            True if `host` resolves to localhost.

        Raises
        ------
        exceptions.HostUnknownException
            If `host` is not known by the system.
        """

        try:
            hn_out = socket.gethostbyname(f"{hostname}")
            if hn_out == "127.0.0.1" or hn_out == "127.0.1.1" or hn_out == "::1":
                self.logger.debug(f"Host '{hostname}' is localhost")
                return True
            elif hostname == socket.gethostname():
                self.logger.debug(
                    f"Host '{hostname}' is localhost, but has no loopback definition!"
                )
                return True
            else:
                self.logger.debug(f"Host '{hostname}' is not localhost")
                return False
        except socket.gaierror:
            raise exceptions.HostUnknownException(
                f"Host '{hostname}' is unknown! Update your /etc/hosts file!"
            )

    def run_on_localhost(self, comp: Component) -> bool:
        """Check whether component `comp` is run on localhost or not.

        Parameters
        ----------
        comp : Component
            Config of component to check.

        Returns
        -------
        bool
            Whether `comp` is run on localhost or remote.

        Raises
        ------
        exceptions.HostUnknownException
            If configured component host is not known by the system.
        """

        try:
            return self.is_localhost(comp["host"])
        except exceptions.HostUnknownException as ex:
            raise ex

    ###################
    # TMUX
    ###################
    def kill_session_by_name(self, name: str) -> None:
        """Kill tmux session by name.

        Parameters
        ----------
        name : str
            Name of the session to be killed.
        """

        self.logger.debug(f"Killing session by name {name}")
        assert self.server is not None
        session = self.server.find_where({"session_name": name})
        if session is not None:
            session.kill_session()
        else:
            self.logger.warning(f"Session with name '{name}' could not be found. Ignoring since it would be killed anyway.")

    def _kill_window(self, window: Window) -> None:
        """Kill tmux window by reference.

        Parameters
        ----------
        window : Window
            Window to be killed.
        """

        self.logger.info(f"Killing window by name {window.name}")
        window.cmd("send-keys", "", "C-c")
        window.kill_window()

    def _start_window(self, window: Window, comp: Component, log_file: str) -> None:
        """Execute cmd in window.

        Mainly used to run a component start command in its designated window

        Parameters
        ----------
        window : Window
            Window the component will be started in
        comp : Component
            Component configuration.
        log_file : str
            Log file path.
        """

        comp_id = comp["id"]

        pid = int(window.pane_pid)
        procs: list[Process] = []
        
        if self._is_window_busy(window):
            procs.extend(Process(pid).children())

        for proc in procs:
            try:
                if proc.is_running():
                    self.logger.debug(f"Killing leftover child process {proc.name()}")
                    proc.terminate()
            except NoSuchProcess:
                pass

        self.logger.debug(f"Rotating log for {comp_id}")
        if len(procs) > 0:
            setup_log(window, log_file, comp_id, False)
        else:
            setup_log(window, log_file, comp_id)

        if self.custom_env_path:
            self.logger.debug(f"Sourcing custom environment for {comp_id}")
            cmd = f". {self.custom_env_path}"
            self._wait_until_window_not_busy(window)
            window.cmd("send-keys", cmd, "Enter")

        self._wait_until_window_not_busy(window)
        self.logger.debug(f"Running start command for {comp_id}")

        start = get_component_cmd(comp, "start")
        window.cmd("send-keys", start, "Enter")

    def _find_window(self, window_name: str) -> Optional[Window]:
        """Find tmux window by name.

        Parameters
        ----------
        window_name : str
            Name of window to find.

        Returns
        -------
        Optional[Window]
            tmux Window if found, None otherwise.
        """

        assert self.session is not None
        window = self.session.find_where({"window_name": window_name})
        return window

    def _get_main_window(self) -> Window:
        """Fetches the main window of the current tmux session.

        Returns
        -------
        Window
            Handle to main tmux window.
        """
        window = self._find_window("Main")
        if window is None:
            self.logger.fatal(f"Main window of session '{self.session_name}' could not be found! Shutting down")
            #TODO: add new Fatal exit state
            self.cleanup(full=True, exit_status=config.ExitStatus.NO_MASTER_RUNNING)
            raise Exception()# call above will exit anyways. This is only for the linter
        return window


    def _send_main_session_command(self, cmd: str) -> None:
        """Send command to the main window of the master session.

        `Session.cmd` sends the command to the currently active window of the session, and when issuing commands to the
        session, usually it is not intended to interact with component windows thus this functions fetches the main
        window and calls the `cmd` function on it.

        Parameters
        ----------
        cmd : str
            Command to execute.
        """

        self.logger.debug(f"Sending command to master session main window: {cmd}")
        window = self._get_main_window()

        self._wait_until_window_not_busy(window)
        window.cmd("send-keys", cmd, "Enter")
        self._wait_until_window_not_busy(window)

    def _wait_until_main_window_not_busy(self) -> None:
        """Blocks until main window of the master session has no child process left running."""

        window = self._get_main_window()
        self._wait_until_window_not_busy(window)

    def _wait_until_window_not_busy(self, window: Window) -> None:
        """Checks whether the passed window is busy executing a process and blocks until it is not busy anymore.

        Parameters
        ----------
        window : Window
            Reference to tmux window which should be waited for.
        """

        self.logger.debug(
            f"Waiting until window '{window.name}' has no running child processes left ..."
        )
        while self._is_window_busy(window):
            sleep(0.1)
        self.logger.debug(f"... window '{window.name}' is not busy anymore")

    def _is_window_busy(self, window: Window) -> bool:
        """Checks whether the window has at least one running child process (excluding tee processes).

        Parameters
        ----------
        window : Window
            tmux window to be checked.

        Returns
        -------
        bool
            True if `window` is busy.
        """

        sc = window.pane_start_command
        cc = window.pane_current_command
        ep = config.SHELL_EXECUTABLE_PATH

        if cc in ['fish', 'zsh', 'bash', 'sh']:
            return False

        assert sc in ep, f"sc should be in ep: ({sc} not in {ep})"
        return cc != ep

    ###################
    # TMUX SESSION CONTROL
    ###################

    def kill_remote_session_by_name(self, name: str, host: str) -> None:
        """Kill tmux session by name `name` on host `host`.

        Parameters
        ----------
        name : str
            Name of the session to kill.
        host : str
            Host that the session runs on.
        """

        cmd = f"ssh -F {config.CUSTOM_SSH_CONFIG_PATH} -t {host} 'tmux kill-session -t {name}'"
        self._send_main_session_command(cmd)

    def start_local_clone_session(self, comp: Component) -> None:
        """Start a local clone session of the master session and open the window of component `comp`.

        Because the libtmux library does not provide functions to achieve this, a bash script is run to automatize the
        process.

        Parameters
        ----------
        comp : Component
            Component whose window is to be shown in the cloned session.
        """

        comp_id = comp["id"]
        cmd = f"{SCRIPT_CLONE_PATH} '{self.session_name}' '{comp_id}'"
        call(cmd, shell=True)

    ####################
    # Do override in subclass
    ####################
    def cleanup(
        self,
        full: bool = False,
        exit_status: config.ExitStatus = config.ExitStatus.FINE,
    ) -> None:
        """Cleanup function for safe shutdown.

        Parameters
        ----------
        full : bool
            Whether this controller instance should also shutdown the server.
        exit_status : config.ExitStatus
            Status context this function was invoked from. The application will exit with that status, by default config.ExitStatus.FINE.

        Raises
        ------
        NotImplementedError
            When the abstract class function is not overridden.
        """
        raise NotImplementedError

    def start_remote_clone_session(self, comp: Component) -> None:
        """Start a clone session of the remote slave session and open the window of component `comp`.

        Parameters
        ----------
        comp : Component
            Component whose window is to be shown in the clone session.

        Raises
        ------
        NotImplementedError
            When the abstract class function is not overridden.
        """
        raise NotImplementedError

    def add_subscriber(self, subscriber: queue.Queue) -> None:
        """Add a queue to the list of subscribers for manager and monitoring thread events.

        Parameters
        ----------
        subscriber : queue.Queue
            Event queue of the subscriber.

        Raises
        ------
        NotImplementedError
            When the abstract class function is not overridden.
        """
        raise NotImplementedError

    def start_all(self, force_mode: bool = False) -> None:
        """Start all components ordered by dependency.

        If force mode is active, each component start is attempted. If not, after a component failed, each component is
        only checked.

        Parameters
        ----------
        force_mode : bool, optional
            Whether to enforce start attempt even if a dependency failed, by default False

        Raises
        ------
        NotImplementedError
            When the abstract class function is not overridden.
        """
        raise NotImplementedError

    def start_component(self, comp: Component, force_mode: bool = False) -> config.StartState:
        """Invoke start of component `comp`.

        Parameters
        ----------
        comp : Component
            Config of component to start.
        force_mode : bool, optional
            Whether starting the the component is tried, even if a dependency is not satisfied, by default False.

        Raises
        ------
        NotImplementedError
            When the abstract class function is not overridden.
        """
        raise NotImplementedError

    def _start_remote_component(self, comp: Component) -> None:
        """Issue start component 'comp' to on remote host.

        Parameters
        ----------
        comp : Component
            Component to start.

        Raises
        ------
        NotImplementedError
            When the abstract class function is not overridden.
        """
        raise NotImplementedError

    def stop_all(self) -> None:
        """Stop all components ordered by dependency and run checks afterwards

        Raises
        ------
        NotImplementedError
            When the abstract class function is not overridden.
        """
        raise NotImplementedError

    def _stop_remote_component(self, comp: Component) -> None:
        """Stops remote component `comp`.

        Parameters
        ----------
        comp : Component
            Component to stop.

        Raises
        ------
        NotImplementedError
            When the abstract class function is not overridden.
        """
        raise NotImplementedError

    def _check_remote_component(self, comp: Component) -> config.CheckState:
        """Run remote component check.

        Parameters
        ----------
        comp : Component
            Component to check.

        Returns
        -------
        config.CheckState
            State of the component.

        Raises
        ------
        NotImplementedError
            When the abstract class function is not overridden.
        """
        raise NotImplementedError

    def reconnect_with_host(self, hostname: str) -> bool:
        """Re-establish master connection to host `hostname`.

        Parameters
        ----------
        hostname : str
            Host to connect to.

        Returns
        -------
        bool
            Whether establishing the connection was successful.

        Raises
        ------
        NotImplementedError
            When the abstract class function is not overridden.
        """
        raise NotImplementedError

    def reload_config(self) -> None:
        """Try reloading configuration file. The old config is saved under a temporary variable that is discarded if
        reloading was successful, but restored if reloading failed at some point (missing file, or dependency errors)

        Raises
        ------
        NotImplementedError
            When the abstract class function is not overridden.
        """
        raise NotImplementedError


class ControlCenter(AbstractController):
    """Controller class that is able to handle a master session."""

    def __init__(
        self,
        configfile: str,
        monitor_enabled: bool = False,
        slave_server: Optional['SlaveManagementServer'] = None,
    ) -> None:
        """Sets up the ControlCenter

        Initializes an empty node dict, an empty host_list dict, creates a queue for monitor jobs and a monitoring
        thread that is started right away and sets a handler for signals. After that the configuration file is loaded
        and a master session with a main window is created if not already existing.

        Parameters
        ----------
        configfile : str, optional
            Path to the configuration to initialize, by default None.
        monitor_enabled : bool, optional
            Whether the monitoring thread should be launched or not, by default False.
        slave_server : SlaveManagementServer, optional
            Socket server managing connection to slaves, by default None.
        """

        super(ControlCenter, self).__init__(configfile)
        self.slave_server = slave_server
        self.nodes: dict[str, Node] = {}

        self.host_states_lock = Lock()

        self.host_states: dict[str, Tuple[int, config.HostConnectionState]] = {f"{socket.gethostname()}": (0, config.HostConnectionState.CONNECTED)}
        """Dictionary that contains the pid the main ssh connection and connection state for each host."""

        self.host_stats = {f"{socket.gethostname()}": config.EMPTY_HOST_STATS}
        """Dictionary containing the current load, cpu, and memory usage stats for each host."""

        if monitor_enabled:
            self.mon_thread.start()

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
                self.session = self.server.find_where(
                    {"session_name": self.session_name}
                )

                self.logger.info(
                    f'found running session by name "{self.session_name}" on server'
                )
                session_ready = True
        except LibTmuxException:
            self.logger.debug(
                "Exception in libtmux while looking up sessions. Maybe no session is running. Trying "
                "to create a new one"
            )

        if not session_ready:
            self.logger.info(
                f'starting new session by name "{self.session_name}" on server'
            )
            self.session = self.server.new_session(
                session_name=self.session_name, window_name="Main"
            )

        if config.MONITOR_LOCAL_STATS:
            self.stat_thread.start()


    ###################
    # Setup
    ###################
    def init(self) -> None:
        """Initialize the controller.

        Sets up master ssh connections to all used hosts, copies components to them if they are reachable and computes a
        dependency tree for all used components.
        """

        if not self.config:
            self.logger.error(" Config not loaded yet!")

        else:
            if not self.config.get("groups"):
                self.logger.critical(
                    "At least one group needs to be defined in your config!"
                )
                self.cleanup(True, config.ExitStatus.CONFIG_PARSING_ERROR)

            if not setup_ssh_config():
                self.cleanup(True, config.ExitStatus.MISSING_SSH_CONFIG)
            try:
                conf_preprocessing(self.config, self.custom_env_path, self.exclude_tags)
            except exceptions.DuplicateGroupDefinitionException as ex:
                self.logger.critical(ex.message)
                self.cleanup(True, config.ExitStatus.CONFIG_PARSING_ERROR)

            for group in self.config["groups"]:
                for comp in group["components"]:
                    try:
                        if comp["host"] != "localhost" and not self.run_on_localhost(
                            comp
                        ):
                            if comp["host"] not in self.host_states:
                                if self._establish_master_connection(comp["host"]):
                                    self.logger.info(
                                        f"Master connection to '{comp['host']}' established!"
                                    )
                    except exceptions.HostUnknownException as ex:
                        self.logger.error(ex.message)

            try:
                self.set_dependencies()
            except (
                exceptions.UnmetDependenciesException,
                exceptions.CircularReferenceException,
            ) as ex:
                self.logger.debug(
                    "Error while setting up dependency tree. Initiating shutdown"
                )
                self.cleanup(True, config.ExitStatus.DEPENDENCY_RESOLUTION_ERROR)

            if self.custom_env_path:
                self.logger.debug(
                    "Sourcing custom environment in main window of master session"
                )
                cmd = f". {self.custom_env_path}"
                self._send_main_session_command(cmd)

            if self.slave_server:
                self.slave_server.start()
            else:
                self.logger.critical("Slave server is None!")

            self.logger.debug("Starting slave on connected remote hosts")
            for host in self.host_states:
                if host and not self.is_localhost(host):
                    self.logger.debug(f"Starting slave on '{host}'")
                    self._start_remote_slave(host)

    def reload_config(self) -> None:
        """
        :return: None
        """

        old_conf = self.config.copy()
        try:
            self._load_config(self.configfile)
        except exceptions.MissingComponentDefinitionException as err:
            self.logger.error(
                f"Reloading failed with error! Included file '{err.filename}' not found!"
            )
            self.config = old_conf
            return
        except IOError as err:
            self.logger.error(f"Reloading failed with error: {err.strerror}")
            self.config = old_conf
            return
        except exceptions.EnvNotFoundException:
            self.logger.error(
                f"Specified environment could not be found. Config reload aborted!"
            )
            self.config = old_conf
            return

        conf_preprocessing(self.config, self.custom_env_path, self.exclude_tags)

        try:
            self.set_dependencies()
        except (
            exceptions.UnmetDependenciesException,
            exceptions.CircularReferenceException,
        ) as ex:
            self.logger.error(
                "Error while setting up dependency tree. Rolling back to working config"
            )
            self.config = old_conf
            try:
                self.set_dependencies()
            except (
                exceptions.UnmetDependenciesException,
                exceptions.CircularReferenceException,
            ) as ex:
                self.logger.critical("Resetting to old config failed!")
                self.cleanup(True, config.ExitStatus.CONFIG_RESET_FAILED)

        # Update hosts
        old_host_states = self.host_states.copy()
        self.host_states = {socket.gethostname(): (0, config.HostConnectionState.CONNECTED)}

        for group in self.config["groups"]:
            for comp in group["components"]:
                try:
                    if comp["host"] != "localhost" and not self.run_on_localhost(comp):
                        if comp["host"] not in self.host_states:
                            if self._establish_master_connection(comp["host"]):
                                self.logger.info(
                                    "Master connection to %s established!"
                                    % comp["host"]
                                )
                except exceptions.HostUnknownException as ex:
                    self.logger.error(ex.message)

        unused_hosts = [k for k in old_host_states if k not in self.host_states]
        if len(unused_hosts) > 0:
            self.logger.debug(
                "Updated config removed hosts from setup - Killing unused remote slaves"
            )
            if self.slave_server is not None:
                for host in unused_hosts:
                    self.slave_server.kill_slave_on_host(host)

        if self.custom_env_path:
            self.logger.debug(
                "Sourcing custom environment in main window of master session"
            )
            cmd = ". %s" % self.custom_env_path
            self._send_main_session_command(cmd)

        if self.slave_server and not self.slave_server.thread.is_alive():
            self.slave_server.start()

        messages = [actionSerializer.serialize_request("conf_reload", [])]

        for host in self.host_states:
            if not self.is_localhost(host):
                if host not in old_host_states:
                    self.logger.debug("Starting slave on '%s'" % host)
                    self._start_remote_slave(host)
                else:
                    self.logger.debug("Updating slave on '%s'" % host)
                    self._start_remote_slave(host, messages)

        self.broadcast_event(events.ConfigReloadEvent(self.config, self.host_states))

    def _start_remote_slave(self, hostname: str, custom_messages: Optional[list[bytes]]=None) -> None:
        """Start slave manager on host 'hostname'.

        Parameters
        ----------
        hostname : str
            Host to start the slave manager on.
        custom_messages : Optional[list[bytes]], optional
            Optional messages to send to a newly connected or reconnected host, by default None.
        """

        if not custom_messages:
            custom_messages = []

        window = self._find_window("ssh-%s" % hostname)
        config_path = "%s/%s.yaml" % (config.TMP_SLAVE_DIR, self.config["name"])

        self.host_stats[hostname] = config.EMPTY_HOST_STATS

        if config.MONITOR_REMOTE_STATS:
            custom_messages.append(
                actionSerializer.serialize_request(
                    "stat_monitoring", [config.REMOTE_STAT_MONITOR_RATE]
                )
            )

        state = self.host_states.get(hostname) 
        if state is None or window is None:
            self.logger.error(
                f"No connection to remote '{hostname}' - can not start slave"
            )
            return
        if self.slave_server is None:
            self.logger.error(
                f"Slave server is not running, cannot start a slave on host '{hostname}'" 
            )
            return

        if not self.slave_server.validate_on_slave(
            hostname, socket.gethostname(), config_path
        ):
            with self.host_states_lock:
                state = self.host_states[hostname]
                self.host_states[hostname] = (state[0], config.HostConnectionState.SSH_ONLY)
            self.logger.error(f"Running hyperion validate on '{hostname}' failed!")
            return

        host_ip = resolve_host_address(hostname, config.CUSTOM_SSH_CONFIG_PATH)
        if self.slave_server.start_slave(
            hostname, host_ip, config_path, self.config["name"], window, custom_messages
        ):
            with self.host_states_lock:
                state = self.host_states[hostname]
                self.host_states[hostname] = (state[0], config.HostConnectionState.CONNECTED)
        else:
            if self._is_window_busy(window):
                self.logger.warn("Remote host slave is still running. Manually check remote tmux session! Maybe the host key of the main server is unknown")
            with self.host_states_lock:
                state = self.host_states[hostname]
                self.host_states[hostname] = (state[0], config.HostConnectionState.SSH_ONLY)

    def set_dependencies(self) -> None:
        """Parses all components constructing a dependency tree.

        :raises exception.UnmetDependencyException: If a component has an unmet dependency
        :return: None
        """
        unmet_deps = False

        provides: dict[str, list[str]] = {}
        requires: dict[str, list[str]] = {}
        optional: dict[str, list[str]] = {}

        for group in self.config["groups"]:
            for comp in group["components"]:
                self.nodes[comp["id"]] = Node(comp)

                # collect provides
                if "provides" in comp:
                    if comp.get("provides"):
                        for entry in comp["provides"]:
                            if provides.get(entry):
                                provides[entry].append(comp["id"])
                            else:
                                provides[entry] = [comp["id"]]
                        if "noauto" in comp:
                            self.logger.warn(
                                '%s is a "noauto" component and a provider for "%s", this is considered bad practice. '
                                "noauto components should not have depending components!"
                                % (comp["id"], entry)
                            )
                    else:
                        self.logger.warn("%s has an empty provides list!" % comp["id"])

                # collect requires
                if "requires" in comp:
                    if comp["requires"]:
                        for entry in comp["requires"]:
                            if requires.get(entry):
                                requires[entry].append(comp["id"])
                            else:
                                requires[entry] = [comp["id"]]
                    else:
                        self.logger.warn("%s has an empty requires list!" % comp["id"])

                if "optional-requires" in comp:
                    if len(comp["optional-requires"]) > 0:
                        for entry in comp["optional-requires"]:
                            if optional.get(entry):
                                optional[entry].append(comp["id"])
                            else:
                                optional[entry] = [comp["id"]]
                    else:
                        self.logger.warn(
                            "%s has an empty optional requires list!" % comp["id"]
                        )

        met_optionals = [k for k in optional if k in provides]
        unmet = [k for k in requires if k not in provides]

        if len(unmet) > 0:
            self.logger.fatal("Unmet requirements were detected! %s" % unmet)
            single_char = 0
            unmet_deps = True

            for deps in unmet:
                if len(unmet):
                    single_char += 1
                    if single_char > 1:
                        self.logger.critical(
                            "Detected unmet dependencies with single char ids. Check that requirement "
                            "definitions in your config are in list-form, even if it is only a single "
                            "component."
                        )
                        break

        if len(optional) > 0:
            self.logger.debug(
                "Detected the following optional requirements available: %s"
                % met_optionals
            )

            for entry in met_optionals:
                if requires.get(entry):
                    requires[entry].extend(optional[entry])
                else:
                    requires[entry] = optional[entry]

        # Add a pseudo node that depends on all other nodes, to get a starting point to be able to iterate through all
        # nodes with simple algorithms
        master_node = Node({"id": "master_node"})

        for requirement, req_list in requires.items():
            for requiring_comp in req_list:
                if provides.get(requirement):
                    for provider in provides[requirement]:
                        self.nodes[requiring_comp].add_edge(
                            self.nodes[provider]
                        )

        for id in self.nodes:
            node = self.nodes[id]

            if id == "master_node":
                continue

            # Add edges from each node to pseudo node
            master_node.add_edge(node)

        self.nodes["master_node"] = master_node

        # Test if starting all components is possible
        try:
            node = self.nodes["master_node"]
            res: list[Node] = []
            unres: list[Node] = []
            dep_resolve(node, res, unres)
            dep_string = ""
            for node in res:
                if node is not master_node:
                    dep_string = "%s -> %s" % (dep_string, node.comp_id)
            self.logger.debug("Dependency tree for start all: %s" % dep_string)
        except exceptions.CircularReferenceException as ex:
            self.logger.error(
                "Detected circular dependency reference between %s and %s!"
                % (ex.node1, ex.node2)
            )
            raise exceptions.CircularReferenceException(ex.node1, ex.node2)
        if unmet_deps:
            raise exceptions.UnmetDependenciesException(unmet)

    def _copy_config_to_remote(self, host: str) -> None:
        """Copy the configuration to a remote machine.

        Parameters
        ----------
        host : str
            Host to copy to.
        """

        self.logger.debug("Dumping config to tmp")
        tmp_conf_path = "%s/%s.yaml" % (config.TMP_CONF_DIR, self.config["name"])
        ensure_dir(tmp_conf_path, mask=config.DEFAULT_LOG_UMASK)

        with open(tmp_conf_path, "w") as outfile:
            clone = self.config.copy()
            if self.custom_env_path:
                clone["env"] = "%s/%s" % (
                    config.TMP_ENV_PATH,
                    os.path.basename(self.custom_env_path),
                )

            dump(clone, outfile, default_flow_style=False)

            self.logger.debug('Copying config to remote host "%s"' % host)
            cmd = "ssh -F %s %s 'mkdir -p %s' && scp %s %s:%s/%s.yaml" % (
                config.CUSTOM_SSH_CONFIG_PATH,
                host,
                config.TMP_SLAVE_DIR,
                tmp_conf_path,
                host,
                config.TMP_SLAVE_DIR,
                self.config["name"],
            )
            self._send_main_session_command(cmd)

    def _copy_env_file(self, host: str) -> None:
        """Copies a custom environment file to source to the remote host `host` if it was specified in the config.

        Parameters
        ----------
        host : str
            Host to copy the file to.
        """ 

        if self.custom_env_path:
            self.logger.debug("Copying custom env file to %s" % host)
            cmd = "ssh -F %s %s 'mkdir -p %s'" % (
                config.CUSTOM_SSH_CONFIG_PATH,
                host,
                config.TMP_ENV_PATH,
            )
            cmd = "%s && scp %s %s:%s/" % (
                cmd,
                os.path.abspath(self.custom_env_path),
                host,
                config.TMP_ENV_PATH,
            )
            self._send_main_session_command(cmd)

    def add_subscriber(self, subscriber_queue: queue.Queue) -> None:
        self.subscribers.append(subscriber_queue)
        self.mon_thread.add_subscriber(subscriber_queue)
        self.stat_thread.add_subscriber(subscriber_queue)

    def remove_subscriber(self, subscriber_queue: queue.Queue) -> None:
        """Remove a queue from the list of subscribers for manager and monitoring thread events.

        Parameters
        ----------
        subscriber_queue : queue.Queue
            Event queue of the subscriber.
        """

        self.subscribers.remove(subscriber_queue)
        self.mon_thread.remove_subscriber(subscriber_queue)
        self.stat_thread.remove_subscriber(subscriber_queue)

    ###################
    # Stop
    ###################
    def _stop_remote_component(self, comp: Component) -> None:
        """Stops remote component `comp`.

        Parameters
        ----------
        comp : Component
            Component to stop.
        """
 
        comp_id = comp["id"]
        host = comp["host"]

        self.logger.debug("Stopping remote component '%s'" % comp_id)
        state = self.host_states.get(host)

        if state is None:
            self.logger.warn(
                f"Host {host} is not connected. Can not stop component {comp_id}!"
            )
            self.broadcast_event(
                events.CheckEvent(comp_id, config.CheckState.UNREACHABLE)
            )
            return

        if state[1] == config.HostConnectionState.CONNECTED:
            self.logger.debug("Issuing stop command to slave server")
            try:
                self.slave_server.stop_component(comp_id, host)
            except exceptions.SlaveNotReachableException as ex:
                self.logger.debug(ex.message)
                self.logger.warn(
                    f"Host {host} is unreachable. Can not stop component {comp_id}!"
                )
                self.broadcast_event(
                    events.CheckEvent(comp_id, config.CheckState.UNREACHABLE)
                )
        elif state[1] == config.HostConnectionState.SSH_ONLY:
            self.logger.error(
                f"Connection state of host {host} is {state[1].name}. Can not stop component {comp_id}!"
            )
            self.broadcast_event(
                events.CheckEvent(comp_id, config.CheckState.NOT_INSTALLED)
            )
        else:
            self.logger.warn(
                f"Connection state of host {host} is {state[1].name}. Can not stop component {comp_id}!"
            )
            self.broadcast_event(
                events.CheckEvent(comp_id, config.CheckState.UNREACHABLE)
            )

    ###################
    # Start
    ###################
    def start_component(self, comp: Component, force_mode: bool = False) -> config.StartState:
        """Invoke dependency based start of component `comp`.

        Traverses the path of dependencies and invokes a call to `start_component_without_deps` for all found
        dependencies before calling it for `comp`.


        Parameters
        ----------
        comp : Component
            Component to start.
        force_mode : bool, optional
            Whether starting the main component is tried, even if a dependency failed, by default False.

        Returns
        -------
        config.StartState
            Result of the starting process.
        """        
        node = self.nodes[comp["id"]]
        res: list[Node] = []
        unres: list[Node] = []
        dep_resolve(node, res, unres)
        hierarchy = resolve_concurrent_start(res)
        
        if config.DEFAULT_THREADN > 1:
            failed_comps = self.start_component_hierarchy_parallel(hierarchy, force_mode, threadn=config.DEFAULT_THREADN)
        else:
            failed_comps = self.start_component_hierarchy(hierarchy, force_mode)

        if len(failed_comps) > 0 and not force_mode:
            return config.StartState.FAILED

        return config.StartState.STARTED

    def start_component_hierarchy(self, hierarchy: list[list[Node]], force_mode: bool = False) -> dict[str, config.CheckState]:
        """Starts a component hierarchy, using a single thread.

        Parameters
        ----------
        hierarchy : list[list[Node]]
            Component hierarchy to be started.
        force_mode : bool, optional
            _description_, by default False

        Returns
        -------
        dict[str, config.CheckState]
            The individual checkstates of the failed components. This is only for internal processing, broadcasting happens along the way.
        """        
        failed_comps: dict[str, config.CheckState] = {}

        for batch in hierarchy:
            if len(failed_comps) > 0 and not force_mode:
                self.logger.error(f"Not in force mode, cancelling dependencies of failed components")
                for comp in batch:
                    self.broadcast_event(events.CheckEvent(comp.comp_id, config.CheckState.DEP_FAILED))
                    failed_comps[comp.comp_id] = config.CheckState.DEP_FAILED
                continue

            self.logger.info(f"Starting the following batch of components: {[c.comp_id for c in batch]}")
            
            for next_comp in batch:
                state = self.component_start_worker_fn(next_comp)
                if (
                    state.check_state is config.CheckState.DEP_FAILED
                    or state.check_state is config.CheckState.STOPPED
                    or state.check_state is config.CheckState.UNREACHABLE
                    or state.check_state is config.CheckState.NOT_INSTALLED
                    or state.check_state is config.CheckState.UNKNOWN
                ):
                    failed_comps[state.comp_id] = state.check_state
                    self.broadcast_event(state)
                    self.logger.error(f"Component {state.comp_id} failed to start!")
        return failed_comps

    def start_component_hierarchy_parallel(self, hierarchy: list[list[Node]], force_mode: bool = False, threadn: int=4) -> dict[str, config.CheckState]:
        """Starts a component hierarchy, using `threadn` threads to start independent components in parallel.

        Parameters
        ----------
        hierarchy : list[list[Node]]
            Component hierarchy to be started.
        force_mode : bool, optional
            _description_, by default False
        threadn : int, optional
            Number of threads for multiprocessing, by default 4

        Returns
        -------
        dict[str, config.CheckState]
            The individual checkstates of the failed components. This is only for internal processing, broadcasting happens along the way.
        """        
        failed_comps: dict[str, config.CheckState] = {}
        pending: deque[AsyncResult[events.CheckEvent]] = deque()
        pool = ThreadPool(processes=threadn)

        for batch in hierarchy:
            if len(failed_comps) > 0 and not force_mode:
                self.logger.error(f"Not in force mode, cancelling dependencies of failed components")
                for comp in batch:
                    self.broadcast_event(events.CheckEvent(comp.comp_id, config.CheckState.DEP_FAILED))
                    failed_comps[comp.comp_id] = config.CheckState.DEP_FAILED
                continue

            self.logger.info(f"Starting the following components in parallel: {[c.comp_id for c in batch]}")
            comp_iter = iter(batch)
            level_done = False
            while not level_done or len(pending) > 0:
                while len(pending) > 0 and pending[0].ready():
                    state = pending.popleft().get()
                    if (
                        state.check_state is config.CheckState.DEP_FAILED
                        or state.check_state is config.CheckState.UNREACHABLE
                        or state.check_state is config.CheckState.NOT_INSTALLED
                        or state.check_state is config.CheckState.UNKNOWN
                    ):
                        failed_comps[state.comp_id] = state.check_state
                        self.broadcast_event(state)
                        self.logger.error(f"Component {state.comp_id} failed to start!")
                if level_done:
                    sleep(0.3)
                elif len(pending) < threadn and not level_done:
                    try:
                        next_comp = next(comp_iter)
                        task = pool.apply_async(self.component_start_worker_fn, (next_comp,))
                        pending.append(task)
                        self.logger.debug(f"Put start job for '{next_comp.comp_id}' in queue")
                    except StopIteration:
                        level_done = True
        return failed_comps

    def component_start_worker_fn(self, node: Node) -> events.CheckEvent:
        """Separate function for a component start with check.

        Parameters
        ----------
        node : Node
            Node to be started.

        Returns
        -------
        events.CheckEvent
            Succesfull CheckEvent if the component was already running or started successfully, non-successful event otherwise.
        """        

        state = self.check_component(node.component, broadcast=False)
        if (
            state is config.CheckState.STOPPED_BUT_SUCCESSFUL
            or state is config.CheckState.STARTED_BY_HAND
            or state is config.CheckState.RUNNING
        ):
            self.logger.debug(
                f"Component '{node.comp_id}' is already running, skipping to next component"
            )
            self.broadcast_event(events.CheckEvent(node.comp_id, state))
            return events.CheckEvent(node.comp_id, state)
        else:
            self.logger.debug(
                f"Starting component '{node.comp_id}'"
            )
            self.start_component_without_deps(node.component)
            # Wait component time for startup
            end_t = time() + get_component_wait(node.component)

            tries = 0
            while True:
                state = self.check_component(node.component, False)
                self.logger.debug(
                    "Checking %s resulted in checkstate %s"
                    % (node.comp_id, config.STATE_DESCRIPTION.get(state))
                )
                if (
                    state is config.CheckState.RUNNING
                    or state is config.CheckState.STOPPED_BUT_SUCCESSFUL
                    or state is config.CheckState.STARTED_BY_HAND
                ):
                    self.logger.debug(f"Dep '{node.comp_id}' success")
                    break
                if time() > end_t:
                    if tries > 2:
                        break
                    tries = tries + 1
                    self.logger.warn(f"Retrying component check for '{node.comp_id}' (failed try {tries})")
                sleep(0.5)
            self.broadcast_event(events.CheckEvent(node.comp_id, state))
            return events.CheckEvent(node.comp_id, state)

    def _start_remote_component(self, comp: Component) -> None:
        """Issue start component 'comp' to slave manager on remote host.

        Parameters
        ----------
        comp : Component
            Component to start.
        """

        comp_id = comp["id"]
        host = comp["host"]

        self.logger.debug("Starting remote component '%s'" % comp_id)
        state = self.host_states.get(comp["host"])

        if state is None:
            self.logger.error(
                f"Host {host} is unreachable. Can not start component {comp_id}!"
            )
            self.broadcast_event(
                events.CheckEvent(comp_id, config.CheckState.UNREACHABLE)
            )
            return

        if state[1] == config.HostConnectionState.CONNECTED:
            try:
                self.logger.debug("Issuing start command to slave server")
                self.slave_server.start_component(comp_id, host)
            except exceptions.SlaveNotReachableException as ex:
                self.logger.debug(ex.message)
                self.logger.warn(
                    f"Host {host} is unreachable. Can not start component {comp_id}!"
                )
                self.broadcast_event(
                    events.CheckEvent(comp_id, config.CheckState.UNREACHABLE)
                )
        elif state[1] == config.HostConnectionState.SSH_ONLY:
            self.logger.error(
                f"Connection state of host {host} is {state[1].name}. Can not start component {comp_id}!"
            )
            self.broadcast_event(
                events.CheckEvent(comp_id, config.CheckState.NOT_INSTALLED)
            )
        else:
            self.logger.warn(
                f"Connection state of host {host} is {state[1].name}. Can not start component {comp_id}!"
            )
            self.broadcast_event(
                events.CheckEvent(comp["id"], config.CheckState.UNREACHABLE)
            )

    def start_all(self, force_mode: bool = False) -> None:
        comps = self.get_start_all_list()
        hierarchy = resolve_concurrent_start(comps)
        if config.DEFAULT_THREADN > 1:
            failed_comps = self.start_component_hierarchy_parallel(hierarchy, force_mode, threadn=config.DEFAULT_THREADN)
        else:
            failed_comps = self.start_component_hierarchy(hierarchy, force_mode)
        self.broadcast_event(events.StartReportEvent("All components", failed_comps))

    def stop_all(self) -> None:
        """Stop all components ordered by dependency and run checks afterwards."""
        
        if config.DEFAULT_THREADN > 1:
            return self.stop_all_parallel()
        
        try:
            comps = self.get_start_all_list(exclude_no_auto=False)
            hierarchy = resolve_concurrent_start(comps)
        except exceptions.CircularReferenceException:
            # If circular dependency is given no components can be started and this is happening in cleanup, so we
            # can safely return without action.
            return

        hierarchy = list(reversed(hierarchy))
        for batch in hierarchy:
            for comp in batch:
                self.stop_component(comp.component)
        for batch in hierarchy:
            for comp in batch:
                self.check_component(comp.component)


    def stop_all_parallel(self) -> None:
        """Stop all components in parallel ordered by dependency and run checks afterwards."""
        try:
            comps = self.get_start_all_list(exclude_no_auto=False)
            hierarchy = resolve_concurrent_start(comps)
        except exceptions.CircularReferenceException:
            # If circular dependency is given no components can be started and this is happening in cleanup, so we
            # can safely return without action.
            return

        pending: deque[AsyncResult[None]] = deque()
        pool = ThreadPool(processes=config.DEFAULT_THREADN)

        hierarchy = list(reversed(hierarchy))

        last_batch: list[Node] = []

        for batch in hierarchy:
            stop_iter = iter(batch)
            check_iter = iter(last_batch)
            both_done = False
            while len(pending) > 0 or not both_done:
                while len(pending) > 0 and pending[0].ready():
                    pending.popleft()
                while len(pending) < config.DEFAULT_THREADN and not both_done:
                    both_done = True
                    try:
                        comp = next(stop_iter)
                        both_done = False
                        task_stop = pool.apply_async(self.stop_component, (comp.component,))
                        pending.append(task_stop)
                    except StopIteration:
                        pass
                    try:
                        comp = next(check_iter)
                        both_done = False
                        task_check = pool.apply_async(self.check_component, (comp.component,))
                        pending.append(task_check)
                    except StopIteration:
                        pass
                else:
                    sleep(0.3)
            last_batch = batch

        # Check final batch
        done = False
        check_iter = iter(last_batch)
        while len(pending) > 0 or not done:
            while len(pending) > 0 and pending[0].ready():
                pending.popleft()
            while len(pending) < config.DEFAULT_THREADN and not done:
                done = True
                try:
                    comp = next(check_iter)
                    done = False
                    task_check = pool.apply_async(self.check_component, (comp.component,))
                    pending.append(task_check)
                except StopIteration:
                    pass
            else:
                sleep(0.3)

    ###################
    # Check
    ###################
    def _check_remote_component(self, comp: Component) -> config.CheckState:
        """Forwards component check to slave manager.

        Parameters
        ----------
        comp : Component
            Component to check.

        Returns
        -------
        config.CheckState
            State of the component.
        """

        self.logger.debug("Starting remote check")
        state = self.host_states.get(comp["host"])
        if state is not None and state[1] == config.HostConnectionState.CONNECTED:
            self.logger.debug("Remote '%s' is connected" % comp["host"])
            if self.slave_server:
                self.logger.debug("Slave server is running")
                try:
                    self.logger.debug("Issuing command to slave server")
                    ret_val = self.slave_server.check_component(
                        comp["id"], comp["host"], get_component_wait(comp)
                    )
                    self.logger.debug("Slave responded %s" % ret_val)
                except exceptions.SlaveNotReachableException as ex:
                    self.logger.debug(ex.message)
                    ret_val = config.CheckState.NOT_INSTALLED
            else:
                ret_val = config.CheckState.UNREACHABLE
        elif state is not None and state[1] == config.HostConnectionState.SSH_ONLY:
            self.logger.error(
                f"Host {comp['host']} has connection status '{state[1]}'. Can not run check for component %s!"
            )
            ret_val = config.CheckState.UNREACHABLE
        else:
            self.logger.error(
                f"Host {comp['host']} is unreachable. Can not run check for component {comp['id']}!"
            )
            ret_val = config.CheckState.UNREACHABLE

        # Create queue event for external notification and return for inner purpose
        self.broadcast_event(events.CheckEvent(comp["id"], ret_val))
        return ret_val

    ###################
    # CLI Functions
    ###################
    def list_components(self) -> list[str]:
        """List all components used by the current configuration.

        :return: List of components
        :rtype: list of str
        """

        return [node.comp_id for _,node in self.nodes.items()]

    def start_by_cli(self, comp_id: str, force_mode: bool = False) -> None:
        """Interface function for starting component by name `comp_id` from the cli.

        Logging information is provided on the INFO level.

        Parameters
        ----------
        comp_id : str
            Id of the component to start (name@host).
        force_mode : bool, optional
            Whether starting should continue when a dependency fails, by default False.
        """

        logger = logging.getLogger("EXECUTE-RESPONSE")

        try:
            comp = self.get_component_by_id(comp_id)
        except exceptions.ComponentNotFoundException as e:
            logger.warning(e.message)
            return

        logger.info("Starting component '%s' ..." % comp_id)
        ret = self.start_component(comp, force_mode)
        if ret is config.StartState.STARTED:
            logger.info("Started component '%s'" % comp_id)
            ret_check = self.check_component(comp)
            logger.info("Check returned status: %s" % config.STATE_DESCRIPTION.get(ret_check))
        elif ret is config.StartState.FAILED:
            logger.info("Starting '%s' failed!" % comp_id)
        elif ret is config.StartState.ALREADY_RUNNING:
            logger.info("Aborted '%s' start: Component is already running!" % comp_id)

    def stop_by_cli(self, comp_id: str) -> None:
        """Interface function for stopping component by name `comp_name` from the cli.

        Logging information is provided on the INFO level.

        Parameters
        ----------
        comp_id : str
            Id of the component to stop (name@host).
        """

        logger = logging.getLogger("EXECUTE-RESPONSE")
        try:
            comp = self.get_component_by_id(comp_id)
        except exceptions.ComponentNotFoundException as e:
            logger.warning(e.message)
            return
        logger.info("Stopping component '%s' ..." % comp_id)
        self.stop_component(comp)
        # sleep(2)
        # ret = self.check_component(comp)
        # logger.info("Check returned status: %s" % ret.name)

    def check_by_cli(self, comp_id: str) -> None:
        """Interface function for checking component by name `comp_name` from the cli.

        Logging information is provided on the INFO level.

        Parameters
        ----------
        comp_id : str
            Id of the component to check (name@host).
        """

        logger = logging.getLogger("EXECUTE-RESPONSE")
        logger.info("Checking component %s ..." % comp_id)
        try:
            comp = self.get_component_by_id(comp_id)
        except exceptions.ComponentNotFoundException as e:
            logger.warning(e.message)
            return
        ret = self.check_component(comp)
        logger.info("Check returned status: %s" % ret.name)

    def start_clone_session_and_attach(self, comp_id: str) -> None:
        """Interface function for show term of component by name `comp_name` from the cli.

        Parameters
        ----------
        comp_id : str
            Id of the component to show (name@host).
        """

        comp = self.get_component_by_id(comp_id)
        try:
            on_localhost = self.run_on_localhost(comp)
        except exceptions.HostUnknownException:
            self.logger.warn(
                "Host '%s' is unknown and therefore not reachable!" % comp["host"]
            )
            return

        if on_localhost:
            self.start_local_clone_session(comp)

            cmd = "%s '%s-clone-session'" % (SCRIPT_SHOW_SESSION_PATH, comp_id)
            call(cmd, shell=True)
        else:
            hostname = comp["host"]
            self.start_remote_clone_session(comp)

            remote_cmd = "%s '%s-clone-session'" % (SCRIPT_SHOW_SESSION_PATH, comp_id)
            cmd = "ssh -tt -F %s %s 'bash -s' < %s" % (
                config.CUSTOM_SSH_CONFIG_PATH,
                hostname,
                remote_cmd,
            )
            call(cmd, shell=True)

    def show_comp_log(self, comp_id: str) -> None:
        """Interface function for viewing the log of component by name `comp_id` from the cli.

        Parameters
        ----------
        comp_id : str
            Id of the component whose log to show (name@host).
        """

        host = comp_id.split("@")[1]
        cmd = '/bin/bash -c "tail -n +1 -F %s/localhost/component/%s/latest.log"' % (
            config.TMP_LOG_PATH,
            comp_id,
        )

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
            cmd = (
                '/bin/bash -c "tail -n +1 -F %s/localhost/component/%s/latest.log"'
                % (config.TMP_LOG_PATH, comp_id)
            )
            try:
                call(
                    "ssh -F %s %s '%s'" % (config.CUSTOM_SSH_CONFIG_PATH, host, cmd),
                    shell=True,
                )
            except KeyboardInterrupt:
                pass

    ###################
    # Dependency management
    ###################
    def get_dep_list(self, comp: Component) -> list[Node]:
        """Get a list of all components that `comp` depends on.

        Parameters
        ----------
        comp : Component
            Component to get dependencies from.

        Returns
        -------
        list[Node]
            The components dependencies.
        """
         
        node = self.nodes[comp["id"]]
        res: list[Node] = []
        unres: list[Node] = []
        dep_resolve(node, res, unres)
        res.remove(node)

        it = list(res)
        [res.remove(entry) if "noauto" in entry.component else "" for entry in it] # type: ignore[func-returns-value]

        return res

    def get_start_all_list(self, exclude_no_auto: bool = True) -> list[Node]:
        """Get a list of all components ordered by dependency (from dependency to depends on).

        Parameters
        ----------
        exclude_no_auto : bool, optional
            Whether to exclude no auto components, by default True.

        Returns
        -------
        list[Node]
            List of components.
        """
        
        node = self.nodes["master_node"]

        if node is None:
            return []

        res: list[Node] = []
        unres: list[Node] = []
        dep_resolve(node, res, unres)
        res.remove(node)

        it = list(res)
        if exclude_no_auto:
            [res.remove(entry) if "noauto" in entry.component else "" for entry in it] # type: ignore[func-returns-value]

        return res

    ###################
    # SSH stuff
    ###################
    def _establish_master_connection(self, hostname: str) -> bool:
        """Create a master ssh connection to host `hostname` in a dedicated window.

        The pid of the ssh session is put into the monitoring thread to have a means to check if the connection still
        exists. Also `host` is added to the list of known hosts with its current status.

        Parameters
        ----------
        hostname : str
            Host to establish a connection with.

        Returns
        -------
        bool
            True establishing the connection was successful.
        """
        
        self.logger.debug("Establishing master connection to host %s" % hostname)

        cmd = "ssh -F %s %s -o BatchMode=yes -o ConnectTimeout=%s -o ControlMaster=yes" % (
            config.CUSTOM_SSH_CONFIG_PATH,
            hostname,
            config.SSH_CONNECTION_TIMEOUT,
        )

        host_ip = resolve_host_address(hostname, config.CUSTOM_SSH_CONFIG_PATH)

        if host_ip is None:
            self.logger.error("Host %s is not reachable!" % hostname)

            with self.host_states_lock:
                self.host_states[hostname] = (0, config.HostConnectionState.DISCONNECTED)
                self.host_stats[hostname] = config.EMPTY_HOST_STATS
            return False

        window = self._find_window("ssh-%s" % hostname)
        if window:
            self.logger.debug("Connecting to '%s' in old window" % hostname)

            if self._is_window_busy(window):
                self.logger.debug("Old connection still alive. No need to reconnect")
            else:
                self.logger.debug("Old connection died. Reconnecting to host")
                window.cmd("send-keys", cmd, "Enter")

        else:
            self.logger.debug("Connecting to '%s' in new window" % hostname)
            assert self.session is not None
            window = self.session.new_window("ssh-%s" % hostname)
            window.cmd("send-keys", cmd, "Enter")

        t_end = time() + config.SSH_CONNECTION_TIMEOUT
        t_min = time() + 0.5

        pid = int(window.pane_pid)
        pids = []

        while time() < t_end:
            procs = []
            procs.extend(Process(pid).children(recursive=False))

            for p in procs:
                try:
                    if p.name() == "ssh":
                        pids.append(p.pid)
                except NoSuchProcess:
                    pass
            if len(pids) > 0 and time() > t_min:
                break

        if len(pids) < 1:
            with self.host_states_lock:
                self.host_states[hostname] = (0, config.HostConnectionState.DISCONNECTED)
                self.host_stats[hostname] = config.EMPTY_HOST_STATS
            return False

        try:
            ssh_proc = Process(pids[0])
        except NoSuchProcess:
            self.logger.debug("ssh process is long gone already. Connection failed")
            self.logger.error(
                "SSH connection was not successful. Make sure that an ssh connection is allowed, "
                "you have set up ssh-keys and the identification certificate is up to date"
            )
            with self.host_states_lock:
                self.host_states[hostname] = (0, config.HostConnectionState.DISCONNECTED)
                self.host_stats[hostname] = config.EMPTY_HOST_STATS
            return False

        # Add host to known list with process to poll from
        with self.host_states_lock:
            self.host_states[hostname] = (pids[0], config.HostConnectionState.SSH_ONLY)
            self.host_stats[hostname] = config.EMPTY_HOST_STATS

        self.logger.debug("Testing if connection was successful")
        if ssh_proc.is_running():
            self.logger.debug("SSH process still running. Connection was successful")
            self.logger.debug("Adding ssh master to monitor queue")
            self.monitor_queue.put(
                HostMonitorJob(hostname, self.host_states, self.host_states_lock)
            )
            self.logger.debug("Copying env files to remote %s" % hostname)
            self._copy_env_file(hostname)
            self._copy_config_to_remote(hostname)
            return True
        else:
            self.logger.error(
                "SSH connection was not successful. Make sure that an ssh connection is allowed, "
                "you have set up ssh-keys and the identification certificate is up to date"
            )
            with self.host_states_lock:
                self.host_states[hostname] = (0, config.HostConnectionState.DISCONNECTED)
                self.host_stats[hostname] = config.EMPTY_HOST_STATS
            return False

    def reconnect_with_host(self, hostname: str) -> bool:
        """Re-establish master connection to host `hostname`

        Parameters
        ----------
        hostname : str
            Host to connect to.

        Returns
        -------
        bool
            Whether establishing the connection was successful or not.
        """

        old_status = self.host_states.get(hostname)

        # Check if really necessary
        self.logger.debug("Reconnecting with %s" % hostname)
        if old_status is not None and old_status[0] > 0:
            proc = Process(old_status[0])
            if not proc.is_running():
                self.logger.debug("Killing off leftover process")
                proc.kill()

        # Start new connection
        if self._establish_master_connection(hostname):
            if old_status is not None and old_status[1] is config.HostConnectionState.DISCONNECTED:
                self.broadcast_event(events.ReconnectEvent(hostname))
            self._start_remote_slave(hostname)
            return True
        else:
            return False

    ###################
    # Safe shutdown
    ###################
    def signal_handler(self, signum: int, frame: Any) -> None:
        """Handler that invokes cleanup on a received signal."""
        self.logger.debug("received signal %s. Running cleanup" % signum)
        self.cleanup()

    def cleanup(self, full: bool = False, status: config.ExitStatus=config.ExitStatus.FINE) -> None:
        """Clean up for safe shutdown.

        Kills the monitoring thread and if full shutdown is requested also the ssh slave sessions and master connections
        and then shuts down the local tmux master session.

        Parameters
        ----------
        full : bool, optional
            Whether the server should be shutdown, too. By default False.
        status : config.ExitStatus, optional
            Status context this function was invoked from. The application will exit with that status, by default config.ExitStatus.FINE
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

            for host in self.host_states:
                window = self._find_window("ssh-%s" % host)

                if window:
                    self.logger.debug("Killing remote slave session of host %s" % host)
                    self.kill_remote_session_by_name("slave-session", host)
                    self.logger.debug("Closing ssh-master window of host %s" % host)
                    self._kill_window(window)

            self.kill_session_by_name(self.session_name)

        self.logger.info("... Done")
        if (status.value != 0 ):
            self.logger.critical(f"{status.name}")
        exit(status.value)

    def start_remote_clone_session(self, comp: Component) -> None:
        comp_id = comp["id"]
        host = comp["host"]

        self.logger.debug("Starting remote clone session for component '%s'" % comp_id)
        state = self.host_states.get(host)
        if state is None:
            self.logger.warn(
                f"Host '{host}' is unreachable. Can not start remote clone session for component {comp_id}!"
            )
            return

        if state[1] == config.HostConnectionState.CONNECTED:
            try:
                self.logger.debug("Issuing start command to slave server")
                self.slave_server.start_clone_session(comp_id, host)
            except exceptions.SlaveNotReachableException as ex:
                self.logger.debug(ex.message)
                self.logger.warn(
                    f"Host '{host}' is unreachable. Can not start remote clone session for component {comp_id}!"
                )
        elif state[1] == config.HostConnectionState.SSH_ONLY:
            self.logger.error(
                f"Connection state of host {host} is {state[1].name}. Can not start clone session for component {comp_id}!"
            )
        else:
            self.logger.warn(
                f"Host '{host}' is unreachable. Can not start remote clone session for component {comp_id}!"
            )


class SlaveManager(AbstractController):
    """Controller class that manages components on a slave machine."""

    def start_remote_clone_session(self, comp: Component) -> None:
        self.logger.error("This function is disabled for slave managers!")
        raise NotImplementedError

    def _stop_remote_component(self, comp: Component) -> None:
        self.logger.error("This function is disabled for slave managers!")
        raise NotImplementedError

    def _start_remote_component(self, comp: Component) -> None:
        self.logger.error("This function is disabled for slave managers!")
        raise NotImplementedError

    def _check_remote_component(self, comp: Component) -> config.CheckState:
        self.logger.error("This function is disabled for slave managers!")
        raise NotImplementedError

    def start_all(self, force_mode: bool = False) -> None:
        self.logger.error("This function is disabled for slave managers!")
        raise NotImplementedError

    def start_local_clone_session(self, comp: Component) -> None:
        session_name = "%s-slave" % self.config["name"]
        comp_id = comp["id"]

        cmd = "%s '%s' '%s'" % (SCRIPT_CLONE_PATH, session_name, comp_id)
        call(cmd, shell=True)

    def reload_config(self) -> None:
        """Try reloading configuration file. The old config is saved under a temporary variable that is discarded if
        reloading was successful, but restored if reloading failed at some point (missing file, or dependency errors).
        """

        old_conf = self.config.copy()

        try:
            self._load_config(self.configfile)
        except exceptions.MissingComponentDefinitionException as err:
            self.logger.error(f"Included file '{err.filename}' not found!")
            self.logger.error("Reloading config failed - falling back to old config!")
            self.config = old_conf
        except IOError:
            self.logger.error("Reloading config failed - falling back to old config!")
            self.config = old_conf
        except exceptions.EnvNotFoundException:
            self.logger.error(
                "Reloading config failed: Env file not found - falling back to old config!"
            )
        self.session_name = f'{self.config["name"]}-slave'
        self.logger.info("Config reload was successful")

    def start_component(self, comp: Component, force_mode: bool = True) -> config.StartState:
        """Start component on this slave.

        This function just calls `start_component_without_deps` because dependencies are managed by the master server.

        Parameters
        ----------
        comp : Component
            Config of component to start.
        force_mode : bool, optional
            Slave always starts without dependency resolution thus this parameter does not affect this subclass implementation.
        """
        self.start_component_without_deps(comp)
        return config.StartState.STARTED # meaningless return to satisfy linter

    def stop_all(self) -> None:
        """Slave only gets forwarded start commands without dependency resolution, thus this function does nothing on a SlaveManager."""
        self.logger.error("This function is disabled for slave managers!")
        raise NotImplementedError

    def reconnect_with_host(self, hostname: str) -> bool:
        """Slave does not connect with other slaves, thus this function does nothing on a SlaveManager."""
        self.logger.error("This function is disabled for slave managers!")
        raise NotImplementedError

    def __init__(self, configfile: str) -> None:
        """Initialize slave manager.

        Parameters
        ----------
        configfile : str
            Path to configuration file.
        """

        super(SlaveManager, self).__init__(configfile)
        self.nodes: dict[str, Node] = {}
        self.host_states = {f"{socket.gethostname()}": (0, config.HostConnectionState.CONNECTED)}
        self.mon_thread.start()

        try:
            self._load_config(configfile)
        except (IOError, exceptions.MissingComponentDefinitionException):
            self.cleanup(exit_status=config.ExitStatus.CONFIG_PARSING_ERROR)
        except exceptions.EnvNotFoundException:
            self.cleanup(exit_status=config.ExitStatus.ENVIRONMENT_FILE_MISSING)
        self.session_name = f'{self.config["name"]}-slave'

        self.logger.info("Loading config was successful")

        self.server = Server()

        session_ready = False
        try:
            if self.server.has_session(self.session_name):
                self.session = self.server.find_where(
                    {"session_name": self.session_name}
                )

                self.logger.info(
                    f"found running session by name '{self.session_name}' on server"
                )
                session_ready = True
        except LibTmuxException:
            self.logger.debug(
                "Exception in libtmux while looking up sessions. Maybe no session is running. Trying "
                "to create a new one"
            )
        if not session_ready:
            self.logger.info(
                f"starting new session by name '{self.session_name}' on server"
            )
            self.session = self.server.new_session(
                session_name=self.session_name, window_name="Main"
            )

    def cleanup(self, full: bool = False, exit_status: config.ExitStatus=config.ExitStatus.FINE) -> None:
        """Clean up for safe shutdown.

        Kills the monitoring thread and if full shutdown is requested also the ssh slave sessions and master connections
        and then shuts down the local tmux master session.

        Parameters
        ----------
        full : bool, optional
            Whether to perform a full shutdown, by default False
        exit_status : _type_, optional
            Status context this function was invoked from. The application will exit with that status, by default config.ExitStatus.FINE
        """

        self.logger.info("Shutting down safely...")

        self.logger.debug("Killing monitoring thread")
        self.mon_thread.kill()
        self.stat_thread.kill()

        if full:
            self.logger.info("Chose full shutdown. Killing tmux sessions")
            self.kill_session_by_name(self.session_name)

        self.logger.info("... Done")
        exit(exit_status.value)

    def add_subscriber(self, subscriber: queue.Queue) -> None:
        self.subscribers.append(subscriber)
        self.mon_thread.add_subscriber(subscriber)
        self.stat_thread.add_subscriber(subscriber)
