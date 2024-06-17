import logging
import logging.handlers
import argparse
import sys
import yaml
import time
import hyperion.lib.util.config as config
from signal import *
from hyperion.lib.util.setupParser import Loader
from hyperion.manager import (
    ControlCenter,
    SlaveManager,
    ensure_dir,
    BASE_DIR,
    rotate_log,
    conf_preprocessing,
)
from hyperion.lib.networking import clientInterface, server
from hyperion.lib.util.config import (
    TMP_LOG_PATH,
    DEFAULT_TCP_PORT,
    ColorFormatter,
    CustomFormatter,
)
from logging.config import fileConfig
from hyperion.lib.util.exception import *

import pkg_resources  # part of setuptools

__version__ = pkg_resources.require("hyperion")[0].version

###########################
# Optional feature imports
###########################
gui_enabled = False
graph_enabled = False
interactive_enabled = False

ui_plugins = {}
for ui_plugin in pkg_resources.iter_entry_points("hyperion.user_interfaces"):
    try:
        ui_plugins.update({ui_plugin.name: ui_plugin.load()})
        print(f"Loaded entry point '{ui_plugin.name}'")
    except ImportError as e:
        print(f"Could not load entry point '{ui_plugin.name}'")

if "urwid" in ui_plugins:
    interactive_enabled = True

if "pyqt" in ui_plugins:
    gui_enabled = True

vis_plugins = {}
for vis_plugin in pkg_resources.iter_entry_points("hyperion.visualisation"):
    try:
        vis_plugins.update({vis_plugin.name: vis_plugin.load()})
        print(f"Loaded entry point '{vis_plugin.name}'")
    except ImportError:
        print(f"Could not load entry point '{vis_plugin.name}'")

if "graph_gen" in vis_plugins:
    graph_enabled = True

ensure_dir(f"{TMP_LOG_PATH}/any.log", mask=config.DEFAULT_LOG_UMASK)

ensure_dir(f"{TMP_LOG_PATH}/localhost/any.log", mask=config.DEFAULT_LOG_UMASK)
ensure_dir(f"{TMP_LOG_PATH}/localhost/client/any.log", mask=config.DEFAULT_LOG_UMASK)
ensure_dir(f"{TMP_LOG_PATH}/localhost/component/any.log", mask=config.DEFAULT_LOG_UMASK)
ensure_dir(f"{TMP_LOG_PATH}/localhost/server/any.log", mask=config.DEFAULT_LOG_UMASK)
ensure_dir(f"{TMP_LOG_PATH}/localhost/slave/any.log", mask=config.DEFAULT_LOG_UMASK)
ensure_dir(
    f"{TMP_LOG_PATH}/localhost/standalone/any.log", mask=config.DEFAULT_LOG_UMASK
)

ensure_dir(f"{TMP_LOG_PATH}/remote/slave/any.log", mask=config.DEFAULT_LOG_UMASK)

fileConfig(f"{BASE_DIR}/data/default-logger.config")


###################
# GUI
###################
def main() -> None:
    """Parse the command line arguments and start hyperion with the specified configuration in the desired mode."""

    logger = logging.getLogger(__name__)
    parser = argparse.ArgumentParser()

    # Version option  for parser
    parser.add_argument(
        "-v", "--version", action="version", version="%(prog)s " + __version__
    )

    # Create top level parser
    subparsers = parser.add_subparsers(dest="cmd")

    # Create parser for server
    subparser_server = subparsers.add_parser("server", help="Starts hyperion backend")
    subparser_server.add_argument("--verbose", action="store_true")
    subparser_server.add_argument(
        "--config",
        "-F",
        type=str,
        help="YAML config file. see sample-config.yaml.",
        required=True,
    )
    subparser_server.add_argument(
        "-p",
        "--port",
        help="Define the tcp port on which the backend will listen for clients. "
        f"Default: {DEFAULT_TCP_PORT}",
        metavar="PORT",
        type=int,
        default=DEFAULT_TCP_PORT,
    )

    # Create parser for the editor command
    subparser_editor = subparsers.add_parser(
        "edit",
        help="Launches the editor to edit or create new systems and " "components",
    )
    subparser_editor.add_argument("--verbose", action="store_true")
    subparser_editor.add_argument(
        "--config",
        "-F",
        type=str,
        help="YAML config file. see sample-config.yaml.",
        required=True,
    )

    # Create parser for the run command
    subparser_cli = subparsers.add_parser(
        "execute",
        help="initialize the configured system with the executing host as "
        "controlling instance. It offers to run a specific action for"
        " a single component or a list of components",
    )
    subparser_cli.add_argument("--verbose", action="store_true")
    subparser_cli.add_argument(
        "--config",
        "-F",
        type=str,
        help="YAML config file. see sample-config.yaml.",
        required=True,
    )

    subparser_cli.add_argument(
        "-C",
        "--component",
        metavar="COMP",
        help="single component or list of components " "specific action",
        default="all",
        nargs="+",
    )
    subparser_cli.add_argument(
        "-f",
        "--force-mode",
        help="set force mode for component start (only makes sense combined with --start flag)",
        dest="force_mode",
        action="store_true",
    )

    comp_mutex = subparser_cli.add_mutually_exclusive_group(required=True)

    comp_mutex.add_argument(
        "-l", "--list", help="List all available components", action="store_true"
    )
    comp_mutex.add_argument(
        "-s",
        "--start",
        help="start the component",
        dest="comp_start",
        action="store_true",
    )
    comp_mutex.add_argument(
        "-k", "--stop", help="Stop the component", dest="comp_stop", action="store_true"
    )
    comp_mutex.add_argument(
        "-c",
        "--check",
        help="Check the component",
        dest="comp_check",
        action="store_true",
    )
    comp_mutex.add_argument(
        "-L",
        "--log",
        help="Show the component log",
        dest="comp_log",
        action="store_true",
    )
    comp_mutex.add_argument(
        "-T",
        "--term",
        help="Show the component term",
        dest="comp_term",
        action="store_true",
    )

    subparser_ui = subparsers.add_parser(
        "ui",
        help="Launches the setup specified by the --config argument and "
        "start with user interface",
    )
    subparser_ui.add_argument("--verbose", action="store_true")

    subparser_ui.add_argument(
        "-p",
        "--port",
        help=f"Specify port to connect to. Defaults to {DEFAULT_TCP_PORT}",
        type=int,
        default=DEFAULT_TCP_PORT,
    )

    ui_mutex = subparser_ui.add_mutually_exclusive_group(required=False)
    ui_mutex.add_argument(
        "-H",
        "--host",
        help="Specify host to connect to. Defaults to localhost",
        default="localhost",
    )
    ui_mutex.add_argument(
        "--config",
        "-F",
        type=str,
        help="YAML config file. see sample-config.yaml. If a config file "
        "is supplied, ui will start in standalone mode!",
    )

    subparser_ui.add_argument(
        "-x",
        help="Use PyQt gui (requires X server and python-qt4 package)",
        dest="x_server",
        action="store_true",
    )

    # Create parser for validator
    subparser_val = subparsers.add_parser(
        "validate", help="Validate the setup specified by the --config argument"
    )
    subparser_val.add_argument("--verbose", action="store_true")
    subparser_val.add_argument(
        "--config",
        "-F",
        type=str,
        help="YAML config file. see sample-config.yaml.",
        required=True,
    )
    subparser_val.add_argument(
        "--visual", help="Generate and show a graph image", action="store_true"
    )

    # Create parser for slave
    subparser_remote = subparsers.add_parser(
        "slave",
        help="Run a component locally without controlling it. The "
        "control is taken care of the remote master invoking "
        "this command.\nIf run with the --kill flag, the "
        "passed component will be killed",
    )
    subparser_remote.add_argument("--verbose", action="store_true")
    subparser_remote.add_argument(
        "--config",
        "-F",
        type=str,
        help="YAML config file. see sample-config.yaml.",
        required=True,
    )

    subparser_remote.add_argument(
        "-p",
        "--port",
        help="specify port of the master server to connect to",
        type=int,
        required=True,
    )

    subparser_remote.add_argument(
        "-H",
        "--host",
        help="specify master server hostname to connect to",
        required=True,
    )

    args = parser.parse_args()
    if args.verbose:
        config.DEFAULT_LOG_LEVEL = logging.DEBUG
    logger.setLevel(config.DEFAULT_LOG_LEVEL)
    logger.debug(args)

    root_logger = logging.getLogger()
    stream_formatter = ColorFormatter()
    for handler in root_logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setFormatter(stream_formatter)
    log_formatter = CustomFormatter()
    log_name = ""

    if args.config:
        try:
            with open(args.config) as data_file:
                tmp_config = yaml.load(data_file, Loader)
                conf_name = tmp_config["name"]
                if conf_name.find(" ") != -1:
                    logger.critical(
                        "Your config name contains at least one space, which is not allowed! Change it"
                    )
                    sys.exit(config.ExitStatus.ERRONEUS_CONFIG.value)
                log_name = f"{conf_name}"
        except MissingComponentDefinitionException as err:
            logger.critical(f"Included file '{err.filename}' not found!")
            sys.exit(config.ExitStatus.CONFIG_NOT_FOUND.value)
        except IOError:
            logger.critical(f"No config file at '{args.config}' found")
            sys.exit(config.ExitStatus.CONFIG_NOT_FOUND.value)

    if args.cmd == "server":
        log_file_path = f"{TMP_LOG_PATH}/localhost/server/{log_name}.log"
        rotate_log(log_file_path, log_name)
        handler = logging.handlers.RotatingFileHandler(log_file_path, "w")

        handler.setFormatter(log_formatter)
        root_logger.addHandler(handler)

        sms = server.SlaveManagementServer()

        logger.debug(f"Starting backend at port: {args.port}")
        cc = ControlCenter(args.config, True, slave_server=sms)
        cc.init()

        s = server.Server(int(args.port), cc)
        sys.exit(config.ExitStatus.FINE.value)

    cc : ControlCenter = None
    if args.cmd == "ui":
        logger.debug("Chose ui mode")

        if args.config:
            log_file_path = (
                f'{TMP_LOG_PATH}/localhost/standalone/{time.strftime("%H-%M-%S")}.log'
            )
            handler = logging.handlers.RotatingFileHandler(log_file_path, "w")

            handler.setFormatter(log_formatter)
            root_logger.addHandler(handler)
            logger.debug("Entering ui in standalone mode")
            sms = server.SlaveManagementServer()
            cc = ControlCenter(args.config, True, slave_server=sms)
            cc.init()

            s = server.Server(int(args.port), cc, loop_in_thread=True)
            rci = clientInterface.RemoteControllerInterface(args.host, args.port)
        else:
            log_file_path = (
                f'{TMP_LOG_PATH}/localhost/client/{time.strftime("%H-%M-%S")}.log'
            )
            rotate_log(log_file_path, log_name)
            handler = logging.handlers.RotatingFileHandler(log_file_path, "w")

            handler.setFormatter(log_formatter)
            root_logger.addHandler(handler)

            logger.debug("Entering ui in socket mode")

            rci = clientInterface.RemoteControllerInterface(args.host, args.port)

        if args.x_server:
            # PyQt
            if gui_enabled:
                logger.debug("Launching GUI runner mode")

                ui = ui_plugins["pyqt"].UiMainWindow(cc)
                signal(SIGINT, SIG_DFL)

                ui_plugins["pyqt"].start_gui(ui)
            else:
                cc.cleanup(False, config.ExitStatus.MISSING_PYQT_INSTALL)
                logger.error(
                    "To use this feature you need PyQt4! Check the README.md for install instructions"
                )
        else:
            # Urwid
            if interactive_enabled:
                remove = []
                for handler in root_logger.handlers:
                    if isinstance(handler, logging.StreamHandler) and not isinstance(
                        handler, logging.FileHandler
                    ):
                        logger.debug(
                            "Remove non file stream handlers to disable logging on stdout!"
                        )
                        remove.append(handler)
                [root_logger.removeHandler(h) for h in remove] # type: ignore[func-returns-value]
                full_shutdown = ui_plugins["urwid"].main(rci, log_file_path)
                # Re-add handlers for shutdown log
                [root_logger.addHandler(h) for h in remove] # type: ignore[func-returns-value]
                rci.cleanup(full_shutdown)
                if cc is not None:
                    s.worker.join()
            else:
                rci.cleanup(False, config.ExitStatus.MISSING_UI_INSTALL)
                if cc is not None:
                    cc.cleanup(True, config.ExitStatus.MISSING_UI_INSTALL)
                logger.error(
                    "To use this feature you need hyperion-uis installed! Check the README.md for install "
                    "instructions. If you already ran the installation try adding site-packages of your "
                    "installation prefix to your PYTHONPATH environment variable."
                )

    if args.cmd == "edit":
        logger.debug("Launching editor mode")

    if args.cmd == "execute":
        clilogger = logging.getLogger("EXECUTE-RESPONSE")
        clilogger.setLevel(logging.INFO)
        logger.info("Launching cli mode")

        for handler in root_logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, logging.FileHandler
            ):
                logger.debug(
                    "Setting non file stream handlers to INFO to disable stdout bloating!"
                )
                handler.setLevel(logging.INFO)

        log_file_path = f"{TMP_LOG_PATH}/localhost/server/{log_name}.log"
        rotate_log(log_file_path, log_name)
        handler = logging.handlers.RotatingFileHandler(log_file_path, "w")

        handler.setFormatter(log_formatter)
        root_logger.addHandler(handler)

        sms = server.SlaveManagementServer()
        cc = ControlCenter(args.config, slave_server=sms)
        cc.init()

        if args.list:
            logger.debug("Chose --list option")
            if args.component != "all":
                logger.warning(
                    "Specifying a component with the -C option is useless in combination with the "
                    "--list option!"
                )
            clilogger.info(
                f"List of all components included in the current configuration:\t{cc.list_components()}"
            )
        else:
            logger.debug("Chose comp specific operation:")
            comps = args.component
            if comps == "all":
                comps = cc.list_components()

            if args.comp_start:
                logger.debug(f"Chose start {args.component}")
                for comp in comps:
                    cc.start_by_cli(comp, args.force_mode)
            if args.comp_stop:
                logger.debug(f"Chose stop {args.component}")
                for comp in comps:
                    cc.stop_by_cli(comp)
            if args.comp_check:
                logger.debug(f"Chose check {args.component}")
                for comp in comps:
                    cc.check_by_cli(comp)
            if args.comp_log:
                logger.debug(f"Chose show log of {args.component}")
                if len(comps) > 1:
                    logger.warning(
                        "The show log option only supports a single component as argument. Only the first is"
                        " used!"
                    )
                cc.show_comp_log(comps[0])
            if args.comp_term:
                logger.debug(f"Chose show term of {args.component}")
                if len(comps) > 1:
                    logger.warning(
                        "The show term option only supports a single component as argument. Only the first"
                        " is used!"
                    )
                cc.start_clone_session_and_attach(comps[0])
            cc.cleanup()

    elif args.cmd == "validate":
        logger.debug("Launching validation mode")
        cc = ControlCenter(args.config)
        conf_preprocessing(cc.config, cc.custom_env_path, cc.exclude_tags)

        if args.visual:
            circular_err_detected = False
            unmet = []
            try:
                cc.set_dependencies()
            except UnmetDependenciesException as e:
                unmet = e.unmet_list
            except CircularReferenceException:
                circular_err_detected = True
                pass

            if graph_enabled:
                vis_plugins["graph_gen"].draw_graph(cc, unmet)
            else:
                logger.error(
                    "To use this feature you need hyperion-graph-vis installed! Check the README.md for "
                    "install instructions. If you already ran the installation try adding site-packages of "
                    "your installation prefix to your PYTHONPATH environment variable."
                )

            if circular_err_detected or len(unmet) > 0:
                cc.cleanup(status=config.ExitStatus.DEPENDENCY_RESOLUTION_ERROR)

        else:
            try:
                cc.set_dependencies()
            except (UnmetDependenciesException, CircularReferenceException):
                cc.cleanup(status=config.ExitStatus.DEPENDENCY_RESOLUTION_ERROR)
        cc.cleanup()

    elif args.cmd == "slave":
        log_file_path = f"{TMP_LOG_PATH}/localhost/slave/{log_name}.log"
        rotate_log(log_file_path, log_name)
        handler = logging.handlers.RotatingFileHandler(log_file_path, "w")

        handler.setFormatter(log_formatter)

        socket_handler = logging.handlers.SocketHandler(args.host, args.port)
        socket_handler.setLevel(logging.INFO)

        memory_handler = logging.handlers.MemoryHandler(
            capacity=1024 * 4000, flushLevel=logging.CRITICAL, target=socket_handler
        )

        root_logger.addHandler(handler)
        root_logger.addHandler(socket_handler)
        root_logger.addHandler(memory_handler)

        logger.debug("Launching slave mode")
        slc = SlaveManager(args.config)
        clientInterface.RemoteSlaveInterface(args.host, args.port, slc)

        logger.debug("Flushing memory handler!")
        memory_handler.close()
        sys.exit(config.ExitStatus.FINE.value)
