#! /usr/bin/env python
from libtmux import Server
from yaml import load, dump
from setupParser import Loader
from DepTree import Node, dep_resolve, CircularReferenceException
import logging
import os
import signal
import socket
import argparse
import uuid
from psutil import Process
from subprocess import call
from enum import Enum
from time import sleep

import sys
###########################
# Optional feature imports
###########################
try:
    from PyQt4 import QtGui
except ImportError:
    gui_enabled = False
else:
    print("Found python-qt. GUI is available")
    import hyperGUI
    gui_enabled = True

try:
    from graphviz import Digraph
except ImportError:
    graph_enabled = False
else:
    print("Found graphviz. Generating dep graph pdf is available")
    graph_enabled = True


FORMAT = "%(asctime)s: %(name)s [%(levelname)s]:\t%(message)s"
DEFAULT_WAIT_TIME = 5.0

logging.basicConfig(level=logging.WARNING, format=FORMAT, datefmt='%I:%M:%S')
TMP_SLAVE_DIR = "/tmp/Hyperion/slave/components"
TMP_COMP_DIR = "/tmp/Hyperion/components"
TMP_LOG_PATH = "/tmp/Hyperion/log"

BASE_DIR = os.path.dirname(__file__)
SCRIPT_CLONE_PATH = ("%s/scripts/start_named_clone_session.sh" % BASE_DIR)


class CheckState(Enum):
    RUNNING = 0
    STOPPED = 1
    STOPPED_BUT_SUCCESSFUL = 2
    STARTED_BY_HAND = 3
    DEP_FAILED = 4


class StartState(Enum):
    STARTED = 0
    ALREADY_RUNNING = 1
    FAILED = 2


class ControlCenter:

    def __init__(self, configfile=None):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.configfile = configfile
        self.nodes = {}
        self.server = []
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
    def load_config(self, filename="default.yaml"):
        with open(filename) as data_file:
            self.config = load(data_file, Loader)

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
            master_node.addEdge(node)

            # Add edges based on dependencies specified in the configuration
            if "depends" in node.component:
                for dep in node.component['depends']:
                    if dep in self.nodes:
                        node.addEdge(self.nodes[dep])
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
        self.logger.debug(cmd)
        send_main_session_command(self.session, cmd)

    def host_reachable(self, hostname):
        # https://stackoverflow.com/questions/2535055/check-if-remote-host-is-up-in-python
        is_up  = True if os.system("ping -c 1 -w 2 " + hostname) is 0 else False
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
            window = find_window(self.session, comp['name'])

            if window:
                self.logger.debug("window '%s' found running" % comp['name'])
                self.logger.info("Shutting down window...")
                kill_window(window)
                self.logger.info("... done!")

    def stop_remote_component(self, comp_name, host):
        # invoke Hyperion in slave mode on each remote host

        if not self.host_list[host]:
            self.logger.error("Host %s is unreachable. Can not stop component %s" % (host, comp_name))
            return

        cmd = ("ssh %s 'hyperion --config %s/%s.yaml slave --kill'" % (host, TMP_SLAVE_DIR, comp_name))
        self.logger.debug("Run cmd:\n%s" % cmd)
        send_main_session_command(self.session, cmd)

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
                    sleep(get_component_wait(comp))

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
            window = find_window(self.session, comp['name'])

            if window:
                self.logger.debug("Restarting '%s' in old window" % comp['name'])
                start_window(window, comp['cmd'][0]['start'], log_file, comp['name'])
            else:
                self.logger.info("creating window '%s'" % comp['name'])
                window = self.session.new_window(comp['name'])
                start_window(window, comp['cmd'][0]['start'], log_file, comp['name'])

    def start_remote_component(self, comp_name, host):
        # invoke Hyperion in slave mode on each remote host

        if not self.host_list[host]:
            self.logger.error("Hot %s is not reachable. Can not start component %s" % (host, comp_name))
            return

        cmd = ("ssh %s 'hyperion --config %s/%s.yaml slave'" % (host, TMP_SLAVE_DIR, comp_name))
        self.logger.debug("Run cmd:\n%s" % cmd)
        send_main_session_command(self.session, cmd)

    ###################
    # Check
    ###################
    def check_component(self, comp):
        if self.run_on_localhost(comp):
            return check_component(comp, self.session, self.logger)
        else:
            self.logger.debug("Starting remote check")
            if self.host_list[comp['host']]:
                cmd = "ssh %s 'hyperion --config %s/%s.yaml slave -c'" % (comp['host'], TMP_SLAVE_DIR, comp['name'])
                ret = call(cmd, shell=True)
                return CheckState(ret)
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

        comp = get_component_by_name(comp_name, self.config)
        if comp == 1:
            logger.info("No component named '%s' was found!" % comp_name)
            return

        logger.info("Starting component '%s' ..." % comp_name)
        ret = self.start_component(comp)
        if ret is StartState.STARTED:
            logger.info("Started component '%s'" % comp_name)
            sleep(get_component_wait(comp))
            ret = check_component(comp, self.session, self.logger)
            logger.info("Check returned status: %s" % ret.name)
        elif ret is StartState.FAILED:
            logger.info("Starting '%s' failed!" % comp_name)
        elif ret is StartState.ALREADY_RUNNING:
            logger.info("Aborted '%s' start: Component is already running!" % comp_name)

    def stop_by_cli(self, comp_name):
        logger = logging.getLogger('CLI-RESPONSE')
        comp = get_component_by_name(comp_name, self.config)
        if comp == 1:
            logger.info("No component named '%s' was found!" % comp_name)
            return
        logger.info("Stopping component '%s' ...")
        self.stop_component(comp)
        sleep(2)
        ret = check_component(comp, self.session, self.logger)
        logger.info("Check returned status: %s" % ret.name)

    def check_by_cli(self, comp_name):
        logger = logging.getLogger('CLI-RESPONSE')
        logger.info("Checking component %s ..." % comp_name)
        comp = get_component_by_name(comp_name, self.config)

        if comp == 1:
            logger.info("No component named '%s' was found!" % comp_name)
            return
        ret = check_component(comp, self.session, self.logger)
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
        send_main_session_command(self.session, cmd)

    def start_clone_session(self, comp_name, session_name):
        cmd = "%s '%s' '%s'" % (SCRIPT_CLONE_PATH, session_name, comp_name)
        send_main_session_command(self.session, cmd)

    def start_remote_clone_session(self, comp_name, session_name, hostname):
        remote_cmd = ("%s '%s' '%s'" % (SCRIPT_CLONE_PATH, session_name, comp_name))
        cmd = "ssh %s 'bash -s' < %s" % (hostname, remote_cmd)
        send_main_session_command(self.session, cmd)

    ###################
    # Visualisation
    ###################
    def draw_graph(self):
        deps = Digraph("Deps", strict=True)
        deps.graph_attr.update(rankdir="BT")
        try:
            node = self.nodes.get('master_node')

            for current in node.depends_on:
                deps.node(current.comp_name)

                res = []
                unres = []
                dep_resolve(current, res, unres)
                for node in res:
                    if "depends" in node.component:
                        for dep in node.component['depends']:
                            if dep not in self.nodes:
                                deps.node(dep, color="red")
                                deps.edge(node.comp_name, dep, "missing", color="red")
                            elif node.comp_name is not "master_node":
                                deps.edge(node.comp_name, dep)

        except CircularReferenceException as ex:
            self.logger.error("Detected circular dependency reference between %s and %s!" % (ex.node1, ex.node2))
            deps.edge(ex.node1, ex.node2, "circular error", color="red")
            deps.edge(ex.node2, ex.node1, color="red")

        deps.view()


class SlaveLauncher:

    def __init__(self, configfile=None, kill_mode=False, check_mode=False):
        self.kill_mode = kill_mode
        self.check_mode = check_mode
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.config = None
        self.session = None
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

    def load_config(self, filename="default.yaml"):
        with open(filename) as data_file:
            self.config = load(data_file, Loader)

    def init(self):
        if not self.config:
            self.logger.error(" Config not loaded yet!")
        elif not self.session:
            self.logger.error(" Init aborted. No session was found!")
        else:
            self.logger.debug(self.config)
            window = find_window(self.session, self.window_name)

            if window:
                self.logger.debug("window '%s' found running" % self.window_name)
                if self.kill_mode:
                    self.logger.info("Shutting down window...")
                    kill_window(window)
                    self.logger.info("... done!")
            elif not self.kill_mode:
                self.logger.info("creating window '%s'" % self.window_name)
                window = self.session.new_window(self.window_name)
                start_window(window, self.config['cmd'][0]['start'], self.log_file, self.window_name)

            else:
                self.logger.info("There is no component running by the name '%s'. Exiting kill mode" %
                                 self.window_name)

    def run_check(self):
        if not self.config:
            self.logger.error(" Config not loaded yet!")
            exit(CheckState.STOPPED.value)
        elif not self.session:
            self.logger.error(" Init aborted. No session was found!")
            exit(CheckState.STOPPED.value)

        check_state = check_component(self.config, self.session, self.logger)
        exit(check_state.value)


###################
# Component Management
###################
def run_component_check(comp):
    if call(comp['cmd'][1]['check'], shell=True) == 0:
        return True
    else:
        return False


def check_component(comp, session, logger):
    logger.debug("Running component check for %s" % comp['name'])
    check_available = len(comp['cmd']) > 1 and 'check' in comp['cmd'][1]
    window = find_window(session, comp['name'])
    if window:
        pid = get_window_pid(window)
        logger.debug("Found window pid: %s" % pid)

        # May return more child pids if logging is done via tee (which then was started twice in the window too)
        procs = []
        for entry in pid:
            procs.extend(Process(entry).children(recursive=True))
        pids = [p.pid for p in procs]
        logger.debug("Window is running %s child processes" % len(pids))

        # TODO: Investigate minimum process number on hosts
        # TODO: Change this when more logging options are introduced
        if len(pids) < 2:
            logger.debug("Main window process has finished. Running custom check if available")
            if check_available and run_component_check(comp):
                logger.debug("Process terminated but check was successful")
                return CheckState.STOPPED_BUT_SUCCESSFUL
            else:
                logger.debug("Check failed or no check available: returning false")
                return CheckState.STOPPED
        elif check_available and run_component_check(comp):
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
        if check_available and run_component_check(comp):
            logger.debug("Component was not started by Hyperion, but the check succeeded")
            return CheckState.STARTED_BY_HAND
        else:
            logger.debug("Window not running and no check command is available or it failed: returning false")
            return CheckState.STOPPED


def get_window_pid(window):
    r = window.cmd('list-panes',
                   "-F #{pane_pid}")
    return [int(p) for p in r.stdout]


def get_component_wait(comp):
    if 'wait' in comp:
        return float(comp['wait'])
    else:
        return DEFAULT_WAIT_TIME


def get_component_by_name(comp_name, config):
    for group in config['groups']:
        for comp in group['components']:
            if comp['name'] == comp_name:
                return comp
    return 1

###################
# TMUX
###################
def kill_session_by_name(server, name):
    session = server.find_where({
        "session_name": name
    })
    session.kill_session()


def kill_window(window):
    window.cmd("send-keys", "", "C-c")
    window.kill_window()


def start_window(window, cmd, log_file, comp_name):
    pid = get_window_pid(window)
    procs = []
    for entry in pid:
        procs.extend(Process(entry).children(recursive=True))

    for proc in procs:
        print("Killing %s" % proc.name())
        os.kill(proc.pid, signal.SIGTERM)

    setup_log(window, log_file, comp_name)
    window.cmd("send-keys", cmd, "Enter")

def find_window(session, window_name):
    window = session.find_where({
        "window_name": window_name
    })
    return window


def send_main_session_command(session, cmd):
    window = find_window(session, "Main")
    window.cmd("send-keys", cmd, "Enter")

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
    #window.cmd("send-keys", "exec 0> >(exec tee -i -a '%s')" % file, "Enter")
    window.cmd("send-keys", ('echo "#Hyperion component start: %s\\t$(date)"' % comp_name), "Enter")


def clear_log(file_path):
    if os.path.isfile(file_path):
        directory = os.path.dirname(file_path)
        os.rename(file_path, "%s/%s.log" % (directory, uuid.uuid4().hex))


def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        

###################
# Startup
###################
def main():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    parser = argparse.ArgumentParser()

    # Create top level parser
    parser.add_argument("--config", '-c', type=str,
                        default='test.yaml',
                        help="YAML config file. see sample-config.yaml. Default: test.yaml")
    subparsers = parser.add_subparsers(dest="cmd")

    # Create parser for the editor command
    subparser_editor = subparsers.add_parser('edit', help="Launches the editor to edit or create new systems and "
                                                          "components")
    # Create parser for the run command
    subparser_cli = subparsers.add_parser('cli', help="Launches the setup specified by the --config argument and "
                                                      "executes the given submode")

    subparser_cli.add_argument('-C', '--component', metavar='COMP', help="single component or list for a component "
                                                                         "specific action", default='all', nargs='+')

    comp_mutex = subparser_cli.add_mutually_exclusive_group(required=True)

    comp_mutex.add_argument('-l', '--list', help="List all available components", action="store_true")
    comp_mutex.add_argument('-s', '--start', help="start the component", dest='comp_start', action="store_true")
    comp_mutex.add_argument('-k', '--stop', help="Stop the component", dest='comp_stop', action="store_true")
    comp_mutex.add_argument('-c', '--check', help="Check the component", dest='comp_check', action="store_true")

    subparser_gui = subparsers.add_parser('gui', help="Launches the setup specified by the --config argument and "
                                                      "start the GUI")

    # Create parser for validator
    subparser_val = subparsers.add_parser('validate', help="Validate the setup specified by the --config argument")

    subparser_remote = subparsers.add_parser('slave', help="Run a component locally without controlling it. The "
                                                           "control is taken care of the remote master invoking "
                                                           "this command.\nIf run with the --kill flag, the "
                                                           "passed component will be killed")

    subparser_val.add_argument("--visual", help="Generate and show a graph image", action="store_true")

    remote_mutex = subparser_remote.add_mutually_exclusive_group(required=False)

    remote_mutex.add_argument('-k', '--kill', help="switch to kill mode", action="store_true")
    remote_mutex.add_argument('-c', '--check', help="Run a component check", action="store_true")

    args = parser.parse_args()
    logger.debug(args)

    if args.cmd == 'edit':
        logger.debug("Launching editor mode")

    if args.cmd == 'cli':
        clilogger = logging.getLogger('CLI-RESPONSE')
        clilogger.setLevel(logging.DEBUG)
        logger.debug("Launching cli mode")

        cc = ControlCenter(args.config)
        cc.init()

        if args.list:
            logger.debug("Chose --list option")
            if args.component != 'all':
                logger.warning("Specifying a component with the -C option is useless in combination with the "
                               "--list option!")
            clilogger.info("List of all components included in the current configuration:\t%s" % cc.list_components())
        else:
            logger.debug("Chose comp specific operation:")
            comps = args.component
            if comps == 'all':
                comps = cc.list_components()

            if args.comp_start:
                logger.debug("Chose start %s" % args.component)
                for comp in comps:
                    cc.start_by_cli(comp)
            if args.comp_stop:
                logger.debug("Chose stop %s" % args.component)
                for comp in comps:
                    cc.stop_by_cli(comp)
            if args.comp_check:
                logger.debug("Chose check %s" % args.component)
                for comp in comps:
                    cc.check_by_cli(comp)

    elif args.cmd == 'gui':
        if gui_enabled:
            logger.debug("Launching GUI runner mode")

            cc = ControlCenter(args.config)
            cc.init()
            start_gui(cc)
        else:
            logger.error("To use this feature you need PyQt4! Check the README.md for install instructions")
            sys.exit(1)

    elif args.cmd == 'validate':
        logger.debug("Launching validation mode")
        cc = ControlCenter(args.config)
        if args.visual:
            cc.set_dependencies(False)
            if graph_enabled:
                cc.draw_graph()
            else:
                logger.error("This feature requires graphviz. To use it install hyperion with the GRAPH option "
                             "(pip install -e .['GRAPH'])")
        else:
            cc.set_dependencies(True)

    elif args.cmd == 'slave':
        logger.debug("Launching slave mode")
        sl = SlaveLauncher(args.config, args.kill, args.check)

        if args.check:
            sl.run_check()
        else:
            sl.init()


###################
# GUI
###################
def start_gui(control_center):
    app = QtGui.QApplication(sys.argv)
    main_window = QtGui.QMainWindow()
    ui = hyperGUI.UiMainWindow()
    ui.ui_init(main_window, control_center)
    main_window.show()
    sys.exit(app.exec_())
