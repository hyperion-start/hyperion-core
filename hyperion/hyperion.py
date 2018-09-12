#! /usr/bin/env python
from libtmux import Server
from yaml import load, dump
from setupParser import Loader
import logging
import os
import argparse

logging.basicConfig(level=logging.WARNING)


class ControlCenter:

    def __init__(self, session_name="session-name", configfile=None):
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
                    self.host_list.append(comp['host'])
                    self.logger.debug('Copying component %s to remote host %s' % (comp['name'], comp['host']))
                    #TODO: Complete SCP command - Component name needs to be substracted!
                    #proc = subprocess.Popen(
                    #    ("scp %s %s:/tmp/Hyperion/slave/components/%s" % (self.configfile, comp['host'], comp['name'])),
                    #    stdout=subprocess.PIPE,
                    #    stderr=subprocess.PIPE,
                    #)

            # Remove duplicate hosts
            self.host_list = list(set(self.host_list))

    def start_remote_components(self):
        # invoke Hyperion in slave mode on each remote host
        # TODO: in the init loop, form a list of components to start for each host to be iterated in this step
        for host in self.host_list:
            if not host == 'localhost':
                #TODO: For each component
                self.logger.debug('Opening connection to remote host %s' % host)
                self.logger.error("Open SSH NYI")
                # TODO: Connect to remote host and start hyperion --config [...] slave

    def start_gui(self):
        self.logger.warn("GUI startup NYI")


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
        logger.debug("Launching editor mode")

    elif args.cmd == 'run':
        logger.debug("Launching runner mode")

        cc = ControlCenter("demo", args.config)
        cc.init()
        cc.start_gui()

    elif args.cmd == 'validate':
        logger.debug("Launching validation mode")
