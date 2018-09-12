#! /usr/bin/env python
from libtmux import Server
from yaml import load, dump
from setupParser import Loader
import logging
import argparse

logging.basicConfig(level=logging.WARNING)


class ControlCenter:

    def __init__(self, session_name="session-name", configfile=None):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.configfile = configfile
        self.server = []
        self.hostlist = []

        if configfile:
            self.load_config(configfile)
            self.session_name = self.config["name"]

            # Debug write resulting yaml file
            with open('debug-result.yml', 'w') as outfile:
                dump(self.config, outfile, default_flow_style=False)
            self.logger.debug("Loading config was successful")

        else:
            self.config = None

    def load_config(self, filename="default.yaml"):
        with open(filename) as data_file:
            self.config = load(data_file, Loader)

    def init(self):
        if not self.config:
            self.logger.error(" Config not loaded yet!")

        #else:
            #TODO: Do stuff

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
