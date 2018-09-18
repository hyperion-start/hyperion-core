#! /usr/bin/env python
from libtmux import Server
from yaml import load, dump
from setupParser import Loader
import logging
import os
import argparse

import sys
from PyQt4 import QtGui
import hyperGUI

logging.basicConfig(level=logging.WARNING)
TMP_SLAVE_DIR = "/tmp/Hyperion/slave/components"
TMP_COMP_DIR = "/tmp/Hyperion/components"
TMP_LOG_PATH = "/tmp/Hyperion/log"


class ControlCenter:

    def __init__(self, configfile=None):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.configfile = configfile
        self.server = []
        self.host_list = []

        if configfile:
            self.load_config(configfile)
            self.session_name = self.config["name"]

            # Debug write resulting yaml file
            with open('debug-result.yml', 'w') as outfile:
                dump(self.config, outfile, default_flow_style=False)
            self.logger.debug("\n\tLoading config was successful")

            self.server = Server()

            if self.server.has_session(self.session_name):
                self.session = self.server.find_where({
                    "session_name": self.session_name
                })

                self.logger.info('found running session by name "%s" on server' % self.session_name)
            else:
                self.logger.info('starting new session by name "%s" on server' % self.session_name)
                self.session = self.server.new_session(
                    session_name=self.session_name
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
                    self.logger.debug("\n\tChecking component '%s' in group '%s'" % (comp['name'], group['name']))

                    if comp['host'] != "localhost":
                        self.copy_component_to_remote(comp, comp['name'], comp['host'])

            # Remove duplicate hosts
            self.host_list = list(set(self.host_list))

    def copy_component_to_remote(self, infile, comp, host):
        self.host_list.append(host)

        self.logger.debug("\n\tSaving component to tmp")
        tmp_comp_path = ('%s/%s.yaml' % (TMP_COMP_DIR, comp))
        ensure_dir(tmp_comp_path)
        with open(tmp_comp_path, 'w') as outfile:
            dump(infile, outfile, default_flow_style=False)

        self.logger.debug('Copying component "%s" to remote host "%s"' % (comp, host))
        cmd = ("ssh %s 'mkdir -p %s' & scp %s %s:%s/%s.yaml" %
               (host, TMP_SLAVE_DIR, tmp_comp_path, host, TMP_SLAVE_DIR, comp))
        self.logger.debug(cmd)
        self.session.cmd("send-keys", cmd, "Enter")

    def start_component(self, comp):
        if comp['host'] != 'localhost':
            self.logger.debug("Starting remote component %s on host %s" % (comp['name'], comp['host']))
            self.start_remote_component(comp['name'], comp['host'])
        else:
            log_file = ("%s/%s" % (TMP_LOG_PATH, comp['name']))
            window = find_window(self.session, comp['name'])

            if window:
                self.logger.debug('window %s found running' % comp['name'])
            else:
                self.logger.info('creating window %s' % comp['name'])
                window = self.session.new_window(comp['name'])
                start_window(window, comp['cmd'][0]['start'], log_file, comp['name'])

            self.logger.debug("starting local component NIY")

    def start_remote_component(self, comp_name, host):
        # invoke Hyperion in slave mode on each remote host
        cmd = ("ssh %s 'hyperion --config %s/%s.yaml slave'" % (host, TMP_SLAVE_DIR, comp_name))
        self.logger.debug("Run cmd:\n%s" % cmd)
        self.session.cmd("send-keys", cmd, "Enter")


class SlaveLauncher:

    def __init__(self, configfile=None, kill_mode=False):
        self.kill_mode = kill_mode
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.config = None
        self.session = None
        if kill_mode:
            self.logger.info("\n\tstarted slave with kill mode")

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
            self.logger.info("\n\tNo slave session found on server. Aborting kill")

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
            window = find_window(self.session, self.window_name)

            if window:
                self.logger.debug('window %s found running' % self.window_name)
                if self.kill_mode:
                    self.logger.info("\n\tShutting down window...")
                    kill_window(window)
                    self.logger.info("\n\t... done!")
            elif not self.kill_mode:
                self.logger.info('creating window %s' % self.window_name)
                window = self.session.new_window(self.window_name)
                start_window(window, self.config['cmd'][0]['start'], self.log_file, self.window_name)

            else:
                self.logger.info("\n\tThere is no component running by the name %s. Exiting kill mode" %
                                 self.window_name)


def start_gui(control_center):
    app = QtGui.QApplication(sys.argv)
    main_window = QtGui.QMainWindow()
    ui = hyperGUI.UiMainWindow()
    ui.ui_init(main_window, control_center)
    main_window.show()
    sys.exit(app.exec_())

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

    subparser_remote.add_argument("--kill", help="switch to kill mode", action="store_true")

    args = parser.parse_args()
    logger.debug(args)

    if args.cmd == 'edit':
        logger.debug("\n\tLaunching editor mode")

    elif args.cmd == 'run':
        logger.debug("\n\tLaunching runner mode")

        cc = ControlCenter(args.config)
        cc.init()
        start_gui(cc)

    elif args.cmd == 'validate':
        logger.debug("\n\tLaunching validation mode")

    elif args.cmd == 'slave':
        logger.debug("\n\tLaunching slave mode")
        sl = SlaveLauncher(args.config, args.kill)
        sl.init()
