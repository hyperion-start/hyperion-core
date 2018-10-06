#! /usr/bin/env python
from libtmux import Server
from yaml import load, dump
from setupParser import Loader
from DepTree import Node, dep_resolve, CircularReferenceException
import logging
import os
import socket
import argparse
from psutil import Process
from subprocess import call
from graphviz import Digraph
from enum import Enum

import sys
from PyQt4 import QtGui
import hyperGUI

FORMAT = "%(asctime)s: %(name)s [%(levelname)s]:\t%(message)s"

logging.basicConfig(level=logging.WARNING, format=FORMAT, datefmt='%I:%M:%S')
TMP_SLAVE_DIR = "/tmp/Hyperion/slave/components"
TMP_COMP_DIR = "/tmp/Hyperion/components"
TMP_LOG_PATH = "/tmp/Hyperion/log"


class CheckState(Enum):
    RUNNING = 0
    STOPPED = 1
    STOPPED_BUT_SUCCESSFUL = 2
    STARTED_BY_HAND = 3


class ControlCenter:

    def __init__(self, configfile=None):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.configfile = configfile
        self.nodes = {}
        self.server = []
        self.host_list = []

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

                    if comp['host'] != "localhost" and self.is_not_localhost(comp['host']):
                        self.copy_component_to_remote(comp, comp['name'], comp['host'])

            # Remove duplicate hosts
            self.host_list = list(set(self.host_list))

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

    def copy_component_to_remote(self, infile, comp, host):
        self.host_list.append(host)

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

    def stop_component(self, comp):
        if comp['host'] != 'localhost' and self.is_not_localhost(comp['host']):
            self.logger.debug("Stopping remote component '%s' on host '%s'" % (comp['name'], comp['host']))
            self.stop_remote_component(comp['name'], comp['host'])
        else:
            window = find_window(self.session, comp['name'])

            if window:
                self.logger.debug("window '%s' found running" % comp['name'])
                self.logger.info("Shutting down window...")
                kill_window(window)
                self.logger.info("... done!")

    def start_component_without_deps(self, comp):
        if comp['host'] != 'localhost' and self.is_not_localhost(comp['host']):
            self.logger.debug("Starting remote component '%s' on host '%s'" % (comp['name'], comp['host']))
            self.start_remote_component(comp['name'], comp['host'])
        else:
            log_file = ("%s/%s" % (TMP_LOG_PATH, comp['name']))
            window = find_window(self.session, comp['name'])

            if window:
                self.logger.debug("window '%s' found running" % comp['name'])
            else:
                self.logger.info("creating window '%s'" % comp['name'])
                window = self.session.new_window(comp['name'])
                start_window(window, comp['cmd'][0]['start'], log_file, comp['name'])

    def start_component(self, comp):

        node = self.nodes.get(comp['name'])
        res = []
        unres = []
        dep_resolve(node, res, unres)
        for node in res:
            if node.comp_name is not comp['name']:
                # TODO: Run component check, if true skip start
                self.logger.debug("Start component '%s' as dependency of '%s'" % (node.comp_name, comp['name']))
                self.start_component_without_deps(node.component)
                self.logger.debug("TODO: run component check!")
                # TODO: Run component check when true continue
            else:
                self.logger.debug("All dependencies satisfied, starting '%s'" % (comp['name']))
                self.start_component_without_deps(comp)

    def stop_remote_component(self, comp_name, host):
        # invoke Hyperion in slave mode on each remote host
        cmd = ("ssh %s 'hyperion --config %s/%s.yaml slave --kill'" % (host, TMP_SLAVE_DIR, comp_name))
        self.logger.debug("Run cmd:\n%s" % cmd)
        send_main_session_command(self.session, cmd)

    def start_remote_component(self, comp_name, host):
        # invoke Hyperion in slave mode on each remote host
        cmd = ("ssh %s 'hyperion --config %s/%s.yaml slave'" % (host, TMP_SLAVE_DIR, comp_name))
        self.logger.debug("Run cmd:\n%s" % cmd)
        send_main_session_command(self.session, cmd)

    def is_not_localhost(self, hostname):
        try:
            hn_out = socket.gethostbyname(hostname)
            if hn_out == '127.0.0.1' or hn_out == '::1' or hn_out == hn_out:
                self.logger.debug("Host '%s' is localhost" % hostname)
                return False
            else:
                self.logger.debug("Host '%s' is not localhost" % hostname)
                return True
        except socket.gaierror:
            sys.exit("Host '%s' is unknown! Update your /etc/hosts file!" % hostname)

    def check_component(self, comp):
        check_available = len(comp['cmd']) > 1 and 'check' in comp['cmd'][1]
        window = find_window(self.session, comp['name'])
        if window:
            pid = get_window_pid(window)
            self.logger.debug("Found window pid: %s" % pid)

            # May return more child pids if logging is done via tee (which then was started twice in the window too)
            procs = []
            for entry in pid:
                procs.extend(Process(entry).children(recursive=True))
            pids = [p.pid for p in procs]
            self.logger.debug("Window is running %s child processes" % len(pids))

            # Two processes are tee logging
            # TODO: Change this when more logging options are introduced
            if len(pids) < 3:
                self.logger.debug("Main window process has finished. Running custom check if available")
                if check_available and run_component_check(comp):
                    self.logger.debug("Process terminated but check was successful")
                    return CheckState.STOPPED_BUT_SUCCESSFUL
                else:
                    self.logger.debug("Check failed or no check available: returning false")
                    return CheckState.STOPPED
            elif check_available and run_component_check(comp):
                self.logger.debug("Check succeeded")
                return CheckState.RUNNING
            elif not check_available:
                self.logger.debug("No custom check specified and got sufficient pid amount: returning true")
                return CheckState.RUNNING
        else:
            self.logger.debug("%s window is not running. Running custom check" % comp['name'])
            if  check_available and run_component_check(comp):
                self.logger.debug("Component was not started by Hyperion, but the check succeeded")
                return CheckState.STARTED_BY_HAND
            else:
                self.logger.debug("Window not running and no check command is available or it failed: returning false")
                return CheckState.STOPPED


class SlaveLauncher:

    def __init__(self, configfile=None, kill_mode=False):
        self.kill_mode = kill_mode
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.config = None
        self.session = None
        if kill_mode:
            self.logger.info("started slave with kill mode")

        self.server = Server()

        if self.server.has_session("slave-session"):
            self.session = self.server.find_where({
                "session_name": "slave-session"
            })

            self.logger.info('found running slave session on server')
        elif not kill_mode:
            self.logger.info('starting new slave session on server')
            self.session = self.server.new_session(
                session_name="slave-session"
            )

        else:
            self.logger.info("No slave session found on server. Aborting kill")

        if configfile:
            self.load_config(configfile)
            self.window_name = self.config['name']
            self.flag_path = ("/tmp/Hyperion/slaves/%s" % self.window_name)
            self.log_file = ("/tmp/Hyperion/log/%s" % self.window_name)
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


def run_component_check(comp):
    if call(comp['cmd'][1]['check'], shell=True) == 0:
        return True
    else:
        return False


def get_window_pid(window):
    r = window.cmd('list-panes',
                   "-F #{pane_pid}")
    return [int(p) for p in r.stdout]


def start_gui(control_center):
    app = QtGui.QApplication(sys.argv)
    main_window = QtGui.QMainWindow()
    ui = hyperGUI.UiMainWindow()
    ui.ui_init(main_window, control_center)
    main_window.show()
    sys.exit(app.exec_())


def kill_session_by_name(server, name):
    session = server.find_where({
        "session_name": name
    })
    session.kill_session()


def send_main_session_command(session, cmd):
    window = find_window(session, "Main")
    window.cmd("send-keys", cmd, "Enter")


def find_window(session, window_name):
            window = session.find_where({
                "window_name": window_name
            })
            return window


def start_window(window, cmd, log_file, comp_name):
    setup_log(window, log_file, comp_name)
    window.cmd("send-keys", cmd, "Enter")


def kill_window(window):
    window.cmd("send-keys", "", "C-c")
    window.kill_window()


def setup_log(window, file, comp_name):
    clear_log(file)
    # Reroute stderr to log file
    window.cmd("send-keys", "exec 2> >(exec tee -i -a '%s')" % file, "Enter")
    # Reroute stdin to log file
    window.cmd("send-keys", "exec 1> >(exec tee -i -a '%s')" % file, "Enter")
    window.cmd("send-keys", ('echo "#Hyperion component start: %s\n$(date)"' % comp_name), "Enter")


def clear_log(file_path):
    if os.path.isfile(file_path):
        os.remove(file_path)


def ensure_dir(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)


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
    subparser_run = subparsers.add_parser('run', help="Launches the setup specified by the --config argument")
    # Create parser for validator
    subparser_val = subparsers.add_parser('validate', help="Validate the setup specified by the --config argument")

    subparser_remote = subparsers.add_parser('slave', help="Run a component locally without controlling it. The "
                                                           "control is taken care of the remote master invoking "
                                                           "this command.\nIf run with the --kill flag, the "
                                                           "passed component will be killed")

    subparser_val.add_argument("--visual", help="Generate and show a graph image", action="store_true")
    subparser_remote.add_argument("--kill", help="switch to kill mode", action="store_true")

    args = parser.parse_args()
    logger.debug(args)

    if args.cmd == 'edit':
        logger.debug("Launching editor mode")

    elif args.cmd == 'run':
        logger.debug("Launching runner mode")

        cc = ControlCenter(args.config)
        cc.init()
        start_gui(cc)

    elif args.cmd == 'validate':
        logger.debug("Launching validation mode")
        cc = ControlCenter(args.config)
        if args.visual:
            cc.set_dependencies(False)
            cc.draw_graph()
        else:
            cc.set_dependencies(True)

    elif args.cmd == 'slave':
        logger.debug("Launching slave mode")
        sl = SlaveLauncher(args.config, args.kill)
        sl.init()
