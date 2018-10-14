#! /usr/bin/env python
from libtmux import Server
from yaml import load, dump
from lib.util.setupParser import Loader
from lib.util.depTree import Node, dep_resolve, CircularReferenceException
import logging
import os
import signal
import socket
import uuid
from psutil import Process
from subprocess import call
from enum import Enum
from time import sleep

import sys

FORMAT = "%(asctime)s: %(name)s %(funcName)20s() [%(levelname)s]:\t%(message)s"
DEFAULT_WAIT_TIME = 5.0

logging.basicConfig(level=logging.WARNING, format=FORMAT, datefmt='%I:%M:%S')
TMP_SLAVE_DIR = "/tmp/Hyperion/slave/components"
TMP_COMP_DIR = "/tmp/Hyperion/components"
TMP_LOG_PATH = "/tmp/Hyperion/log"

BASE_DIR = os.path.dirname(__file__)
SCRIPT_CLONE_PATH = ("%s/bin/start_named_clone_session.sh" % BASE_DIR)


class CheckState(Enum):
    RUNNING = 0
    STOPPED = 1
    STOPPED_BUT_SUCCESSFUL = 2
    STARTED_BY_HAND = 3
    DEP_FAILED = 4
    UNREACHABLE = 5
    NOT_INSTALLED = 6


class StartState(Enum):
    STARTED = 0
    ALREADY_RUNNING = 1
    FAILED = 2


###################
# Logging
###################
def setup_log(window, file, comp_name):
    clear_log(file)
    ensure_dir(file)

    window.cmd("send-keys", "exec > /dev/tty", "Enter")

    # Reroute stderr to log file
    window.cmd("send-keys", "exec 2> >(exec tee -i -a '%s')" % file, "Enter")
    # Reroute stdout to log file
    window.cmd("send-keys", "exec 1> >(exec tee -i -a '%s')" % file, "Enter")
    # Reroute stdin to log file <== causes remote host to logout, disabled for now
    # window.cmd("send-keys", "exec 0> >(exec tee -i -a '%s')" % file, "Enter")
    window.cmd("send-keys", ('echo "#Hyperion component start: %s\\t$(date)"' % comp_name), "Enter")


def clear_log(file_path):
    if os.path.isfile(file_path):
        directory = os.path.dirname(file_path)
        os.rename(file_path, "%s/%s.log" % (directory, uuid.uuid4().hex))


def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)


class AbstractController(object):

    def __init__(self, configfile):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.configfile = configfile
        self.config = None
        self.session = None
        self.server = None

    def load_config(self, filename="default.yaml"):
        with open(filename) as data_file:
            self.config = load(data_file, Loader)

    ###################
    # Component Management
    ###################
    def run_component_check(self, comp):
        self.logger.debug("Running specific component check for %s" % comp['name'])
        if call(comp['cmd'][1]['check'], shell=True) == 0:
            self.logger.debug("Check returned true")
            return True
        else:
            self.logger.debug("Check returned false")
            return False

    def check_local_component(self, comp):
        logger = self.logger

        logger.debug("Running component check for %s" % comp['name'])
        check_available = len(comp['cmd']) > 1 and 'check' in comp['cmd'][1]
        window = self.find_window(comp['name'])
        if window:
            pid = self.get_window_pid(window)
            logger.debug("Found window pid: %s" % pid)

            # May return more child pids if logging is done via tee (which then was started twice in the window too)
            procs = []
            for entry in pid:
                procs.extend(Process(entry).children(recursive=True))

            pids = []
            for p in procs:
                if p.name != 'tee':
                    pids.append(p.pid)
            logger.debug("Window is running %s non-logger child processes: %s" % (len(pids), pids))

            if len(pids) < 1:
                logger.debug("Main process has finished. Running custom check if available")
                if check_available and self.run_component_check(comp):
                    logger.debug("Process terminated but check was successful")
                    return CheckState.STOPPED_BUT_SUCCESSFUL
                else:
                    logger.debug("Check failed or no check available: returning false")
                    return CheckState.STOPPED
            elif check_available and self.run_component_check(comp):
                logger.debug("Check succeeded")
                return CheckState.RUNNING
            elif not check_available:
                logger.debug("No custom check specified and got sufficient pid amount: returning true")
                return CheckState.RUNNING
            else:
                logger.debug("Check failed: returning false")
                return CheckState.STOPPED
        else:
            logger.debug("%s window is not running. Running custom check" % comp['name'])
            if check_available and self.run_component_check(comp):
                logger.debug("Component was not started by Hyperion, but the check succeeded")
                return CheckState.STARTED_BY_HAND
            else:
                logger.debug("Window not running and no check command is available or it failed: returning false")
                return CheckState.STOPPED

    def get_window_pid(self, window):
        self.logger.debug("Fetching pids of window %s" % window.name)
        r = window.cmd('list-panes',
                       "-F #{pane_pid}")
        return [int(p) for p in r.stdout]

    def get_component_wait(self, comp):
        self.logger.debug("Retrieving wait time of component %s" % comp['name'])
        if 'wait' in comp:
            self.logger.debug("Found %s seconds as wait time for %s" % (float(comp['wait']), comp['name']))
            return float(comp['wait'])
        else:
            self.logger.debug("No wait time for %s found, using default of %s seconds" % (comp['name'],
                                                                                          DEFAULT_WAIT_TIME))
            return DEFAULT_WAIT_TIME

    def get_component_by_name(self, comp_name):
        self.logger.debug("Searching for %s in components" % comp_name)
        for group in self.config['groups']:
            for comp in group['components']:
                if comp['name'] == comp_name:
                    self.logger.debug("Component %s found" % comp_name)
                    return comp
        self.logger.warning("Component %s not found in current configuration" % comp_name)
        return 1

    ###################
    # TMUX
    ###################
    def kill_session_by_name(self, name):
        self.logger.debug("Killing session by name %s" % name)
        session = self.server.find_where({
            "session_name": name
        })
        session.kill_session()

    def kill_window(self, window):
        self.logger.debug("Killing window by name %s" % window.name)
        window.cmd("send-keys", "", "C-c")
        window.kill_window()

    def start_window(self, window, cmd, log_file, comp_name):
        pid = self.get_window_pid(window)
        procs = []
        for entry in pid:
            procs.extend(Process(entry).children(recursive=True))

        for proc in procs:
            self.logger.debug("Killing leftover child process %s" % proc.name())
            os.kill(proc.pid, signal.SIGTERM)

        self.logger.debug("Rotating log for %s" % comp_name)
        setup_log(window, log_file, comp_name)
        self.logger.debug("Running start command for %s" % comp_name)
        window.cmd("send-keys", cmd, "Enter")

    def find_window(self, window_name):
        window = self.session.find_where({
            "window_name": window_name
        })
        return window

    def send_main_session_command(self, cmd):
        self.logger.debug("Sending command to master session main window: %s" % cmd)
        window = self.find_window('Main')
        window.cmd("send-keys", cmd, "Enter")


class ControlCenter(AbstractController):

    def __init__(self, configfile=None):
        super(ControlCenter, self).__init__(configfile)
        self.nodes = {}
        self.host_list = {}

        if configfile:
            self.load_config(configfile)
            self.session_name = self.config["name"]

            # Debug write resulting yaml file
            with open('debug-result.yml', 'w') as outfile:
                dump(self.config, outfile, default_flow_style=False)
            self.logger.debug("Loading config was successful")

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
        if not self.config:
            self.logger.error(" Config not loaded yet!")

        else:
            for group in self.config['groups']:
                for comp in group['components']:
                    self.logger.debug("Checking component '%s' in group '%s' on host '%s'" %
                                      (comp['name'], group['name'], comp['host']))

                    if comp['host'] != "localhost" and not self.run_on_localhost(comp):
                        if comp['host'] not in self.host_list:
                            if self.host_reachable(comp['host']):
                                self.copy_component_to_remote(comp, comp['name'], comp['host'])
                                self.host_list[comp['host']] = True
                            else:
                                self.host_list[comp['host']] = False

            self.set_dependencies(True)

    def set_dependencies(self, exit_on_fail):
        for group in self.config['groups']:
            for comp in group['components']:
                self.nodes[comp['name']] = Node(comp)

        # Add a pseudo node that depends on all other nodes, to get a starting point to be able to iterate through all
        # nodes with simple algorithms
        master_node = Node({'name': 'master_node'})
        for name in self.nodes:
            node = self.nodes.get(name)

            # Add edges from each node to pseudo node
            master_node.add_edge(node)

            # Add edges based on dependencies specified in the configuration
            if "depends" in node.component:
                for dep in node.component['depends']:
                    if dep in self.nodes:
                        node.add_edge(self.nodes[dep])
                    else:
                        self.logger.error("Unmet dependency: '%s' for component '%s'!" % (dep, node.comp_name))
                        if exit_on_fail:
                            exit(1)
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
                    dep_string = "%s -> %s" % (dep_string, node.comp_name)
            self.logger.debug("Dependency tree for start all: %s" % dep_string)
        except CircularReferenceException as ex:
            self.logger.error("Detected circular dependency reference between %s and %s!" % (ex.node1, ex.node2))
            if exit_on_fail:
                exit(1)

    def copy_component_to_remote(self, infile, comp, host):
        self.logger.debug("Saving component to tmp")
        tmp_comp_path = ('%s/%s.yaml' % (TMP_COMP_DIR, comp))
        ensure_dir(tmp_comp_path)
        with open(tmp_comp_path, 'w') as outfile:
            dump(infile, outfile, default_flow_style=False)

        self.logger.debug('Copying component "%s" to remote host "%s"' % (comp, host))
        cmd = ("ssh %s 'mkdir -p %s' & scp %s %s:%s/%s.yaml" %
               (host, TMP_SLAVE_DIR, tmp_comp_path, host, TMP_SLAVE_DIR, comp))
        self.send_main_session_command(cmd)

    def host_reachable(self, hostname):
        # https://stackoverflow.com/questions/2535055/check-if-remote-host-is-up-in-python
        is_up = True if os.system("ping -c 1 -w 2 " + hostname) is 0 else False
        if is_up:
            self.logger.debug("Host %s is reachable via ping" % hostname)
            ssh_success = True if os.system("ssh %s -n -o BatchMode=yes -o ConnectTimeout=5" % hostname) is 0 else False
            if ssh_success:
                self.logger.debug("ssh connection to %s succeeded" % hostname)
                return True
            else:
                self.logger.error("ssh connection to %s failed! Check if an ssh connection is allowed or if the "
                                  "certificate has to be renewed" % hostname)
                return False
        else:
            self.logger.error("Host %s not reachable" % hostname)
            return False

    ###################
    # Stop
    ###################
    def stop_component(self, comp):
        if comp['host'] != 'localhost' and not self.run_on_localhost(comp):
            self.logger.debug("Stopping remote component '%s' on host '%s'" % (comp['name'], comp['host']))
            self.stop_remote_component(comp['name'], comp['host'])
        else:
            window = self.find_window(comp['name'])

            if window:
                self.logger.debug("window '%s' found running" % comp['name'])
                self.logger.info("Shutting down window...")
                self.kill_window(window)
                self.logger.info("... done!")

    def stop_remote_component(self, comp_name, host):
        # invoke Hyperion in slave kill mode on remote host

        if not self.host_list[host]:
            self.logger.error("Host %s is unreachable. Can not stop component %s" % (host, comp_name))
            return

        cmd = ("ssh %s 'hyperion --config %s/%s.yaml slave --kill'" % (host, TMP_SLAVE_DIR, comp_name))
        self.send_main_session_command(cmd)

    ###################
    # Start
    ###################
    def start_component(self, comp):

        node = self.nodes.get(comp['name'])
        res = []
        unres = []
        dep_resolve(node, res, unres)
        for node in res:
            self.logger.debug("node name '%s' vs. comp name '%s'" % (node.comp_name, comp['name']))
            if node.comp_name != comp['name']:
                self.logger.debug("Checking and starting %s" % node.comp_name)
                state = self.check_component(node.component)
                if (state is CheckState.STOPPED_BUT_SUCCESSFUL or
                        state is CheckState.STARTED_BY_HAND or
                        state is CheckState.RUNNING):
                    self.logger.debug("Component %s is already running, skipping to next in line" % comp['name'])
                else:
                    self.logger.debug("Start component '%s' as dependency of '%s'" % (node.comp_name, comp['name']))
                    self.start_component_without_deps(node.component)

                    # Wait component time for startup
                    sleep(self.get_component_wait(comp))

                    tries = 0
                    while True:
                        self.logger.debug("Checking %s resulted in checkstate %s" % (node.comp_name, state))
                        state = self.check_component(node.component)
                        if (state is not CheckState.RUNNING or
                           state is not CheckState.STOPPED_BUT_SUCCESSFUL):
                            break
                        if tries > 10:
                            return StartState.FAILED
                        tries = tries + 1
                        sleep(.5)

        self.logger.debug("All dependencies satisfied, starting '%s'" % (comp['name']))
        state = self.check_component(node.component)
        if (state is CheckState.STARTED_BY_HAND or
                state is CheckState.RUNNING):
            self.logger.debug("Component %s is already running. Skipping start" % comp['name'])
            return StartState.ALREADY_RUNNING
        else:
            self.start_component_without_deps(comp)
        return StartState.STARTED

    def start_component_without_deps(self, comp):
        if comp['host'] != 'localhost' and not self.run_on_localhost(comp):
            self.logger.debug("Starting remote component '%s' on host '%s'" % (comp['name'], comp['host']))
            self.start_remote_component(comp['name'], comp['host'])
        else:
            log_file = ("%s/%s/latest.log" % (TMP_LOG_PATH, comp['name']))
            window = self.find_window(comp['name'])

            if window:
                self.logger.debug("Restarting '%s' in old window" % comp['name'])
                self.start_window(window, comp['cmd'][0]['start'], log_file, comp['name'])
            else:
                self.logger.info("creating window '%s'" % comp['name'])
                window = self.session.new_window(comp['name'])
                self.start_window(window, comp['cmd'][0]['start'], log_file, comp['name'])

    def start_remote_component(self, comp_name, host):
        # invoke Hyperion in slave mode on each remote host

        if not self.host_list[host]:
            self.logger.error("Hot %s is not reachable. Can not start component %s" % (host, comp_name))
            return

        cmd = ("ssh %s 'hyperion --config %s/%s.yaml slave'" % (host, TMP_SLAVE_DIR, comp_name))
        self.send_main_session_command(cmd)

    ###################
    # Check
    ###################
    def check_component(self, comp):
        if self.run_on_localhost(comp):
            return self.check_local_component(comp)
        else:
            self.logger.debug("Starting remote check")
            if self.host_list[comp['host']]:
                cmd = "ssh %s 'hyperion --config %s/%s.yaml slave -c'" % (comp['host'], TMP_SLAVE_DIR, comp['name'])
                ret = call(cmd, shell=True)
                try:
                    return CheckState(ret)
                except ValueError:
                    return CheckState.NOT_INSTALLED
            else:
                self.logger.error("Host %s is unreachable. Can not run check for component %s!" % (comp['host'],
                                                                                                   comp['name']))
                # TODO: add unreachable CheckState
                return CheckState.STOPPED

    ###################
    # CLI Functions
    ###################
    def list_components(self):
        return [self.nodes.get(node).comp_name for node in self.nodes]

    def start_by_cli(self, comp_name):
        logger = logging.getLogger('CLI-RESPONSE')

        comp = self.get_component_by_name(comp_name)
        if comp == 1:
            logger.info("No component named '%s' was found!" % comp_name)
            return

        logger.info("Starting component '%s' ..." % comp_name)
        ret = self.start_component(comp)
        if ret is StartState.STARTED:
            logger.info("Started component '%s'" % comp_name)
            sleep(self.get_component_wait(comp))
            ret = self.check_component(comp)
            logger.info("Check returned status: %s" % ret.name)
        elif ret is StartState.FAILED:
            logger.info("Starting '%s' failed!" % comp_name)
        elif ret is StartState.ALREADY_RUNNING:
            logger.info("Aborted '%s' start: Component is already running!" % comp_name)

    def stop_by_cli(self, comp_name):
        logger = logging.getLogger('CLI-RESPONSE')
        comp = self.get_component_by_name(comp_name)
        if comp == 1:
            logger.info("No component named '%s' was found!" % comp_name)
            return
        logger.info("Stopping component '%s' ...")
        self.stop_component(comp)
        sleep(2)
        ret = self.check_component(comp)
        logger.info("Check returned status: %s" % ret.name)

    def check_by_cli(self, comp_name):
        logger = logging.getLogger('CLI-RESPONSE')
        logger.info("Checking component %s ..." % comp_name)
        comp = self.get_component_by_name(comp_name)

        if comp == 1:
            logger.info("No component named '%s' was found!" % comp_name)
            return
        ret = self.check_component(comp)
        logger.info("Check returned status: %s" % ret.name)

    def start_clone_session_and_attach(self, comp_name):
        self.logger.debug("NYI")

    def show_comp_log(self, comp_name):
        self.logger.debug("NYI")

    ###################
    # Dependency management
    ###################
    def get_dep_list(self, comp):
        node = self.nodes.get(comp['name'])
        res = []
        unres = []
        dep_resolve(node, res, unres)
        res.remove(node)

        return res

    ###################
    # Host related checks
    ###################
    def is_localhost(self, hostname):
        try:
            hn_out = socket.gethostbyname(hostname)
            if hn_out == '127.0.0.1' or hn_out == '::1':
                self.logger.debug("Host '%s' is localhost" % hostname)
                return True
            else:
                self.logger.debug("Host '%s' is not localhost" % hostname)
                return False
        except socket.gaierror:
            sys.exit("Host '%s' is unknown! Update your /etc/hosts file!" % hostname)

    def run_on_localhost(self, comp):
        return self.is_localhost(comp['host'])

    ###################
    # TMUX
    ###################
    def kill_remote_session_by_name(self, name, host):
        cmd = "ssh -t %s 'tmux kill-session -t %s'" % (host, name)
        self.send_main_session_command(cmd)

    def start_clone_session(self, comp_name, session_name):
        cmd = "%s '%s' '%s'" % (SCRIPT_CLONE_PATH, session_name, comp_name)
        self.send_main_session_command(cmd)

    def start_remote_clone_session(self, comp_name, session_name, hostname):
        remote_cmd = ("%s '%s' '%s'" % (SCRIPT_CLONE_PATH, session_name, comp_name))
        cmd = "ssh %s 'bash -s' < %s" % (hostname, remote_cmd)
        self.send_main_session_command(cmd)


class SlaveLauncher(AbstractController):

    def __init__(self, configfile, kill_mode=False, check_mode=False):
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

            self.logger.info('found running slave session on server')
        elif not kill_mode and not check_mode:
            self.logger.info('starting new slave session on server')
            self.session = self.server.new_session(
                session_name="slave-session"
            )

        else:
            self.logger.info("No slave session found on server. Aborting")
            exit(CheckState.STOPPED)

        if configfile:
            self.load_config(configfile)
            self.window_name = self.config['name']
            self.log_file = ("%s/%s/latest.log" % (TMP_LOG_PATH, self.window_name))
            ensure_dir(self.log_file)
        else:
            self.logger.error("No slave component config provided")

    def init(self):
        if not self.config:
            self.logger.error(" Config not loaded yet!")
        elif not self.session:
            self.logger.error(" Init aborted. No session was found!")
        else:
            self.logger.debug(self.config)
            window = self.find_window(self.window_name)

            if window:
                self.logger.debug("window '%s' found running" % self.window_name)
                if self.kill_mode:
                    self.logger.info("Shutting down window...")
                    self.kill_window(window)
                    self.logger.info("... done!")
            elif not self.kill_mode:
                self.logger.info("creating window '%s'" % self.window_name)
                window = self.session.new_window(self.window_name)
                self.start_window(window, self.config['cmd'][0]['start'], self.log_file, self.window_name)

            else:
                self.logger.info("There is no component running by the name '%s'. Exiting kill mode" %
                                 self.window_name)

    def run_check(self):
        if not self.config:
            self.logger.error("Config not loaded yet!")
            exit(CheckState.STOPPED.value)
        elif not self.session:
            self.logger.error("Init aborted. No session was found!")
            exit(CheckState.STOPPED.value)

        check_state = self.check_local_component(self.config)
        exit(check_state.value)
