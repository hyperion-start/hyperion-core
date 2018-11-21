import logging
import logging.handlers
import argparse
import sys
from signal import *
from manager import ControlCenter, SlaveLauncher, ensure_dir, BASE_DIR
from lib.util.depTree import CircularReferenceException, dep_resolve
from lib.networking.server import Server
from lib.networking import clientInterface
from lib.util.config import TMP_LOG_PATH, DEFAULT_TCP_PORT
from logging.config import fileConfig

###########################
# Optional feature imports
###########################
try:
    from PyQt4 import QtGui
except ImportError:
    gui_enabled = False
else:
    import user_interfaces.hyperGUI as hyperGUI
    gui_enabled = True

try:
    from graphviz import Digraph
except ImportError:
    graph_enabled = False
else:
    graph_enabled = True

try:
    import user_interfaces.interactiveCLI as interactiveCLI
except ImportError:
    interactive_enabled = False
else:
    interactive_enabled = True

ensure_dir("%s/any.log" % TMP_LOG_PATH)
fileConfig('%s/data/default-logger.config' % BASE_DIR)


###################
# GUI
###################
def start_gui(control_center, ui):
    """Start the PyQt4 guided interface.

    :param control_center: Manager holding the configuration
    :type control_center: ControlCenter
    :param ui: User interface to display
    :type ui: hyperGUI.UiMainWindow
    :return: None
    """

    app = QtGui.QApplication(sys.argv)
    main_window = QtGui.QMainWindow()
    ui.ui_init(main_window, control_center)
    app.aboutToQuit.connect(ui.close)
    main_window.show()
    app.exec_()


###################
# Visualisation
###################
def draw_graph(control_center):
    """Generate and open a dependency graph pdf with graphviz.

    :param control_center: Manager holding the configuration to generate.
    :type control_center: ControlCenter
    :return: None
    """

    deps = Digraph("Deps", strict=True)
    deps.graph_attr.update(rankdir="BT")
    try:
        node = control_center.nodes.get('master_node')

        for current in node.depends_on:
            deps.node(current.comp_name)

            res = []
            unres = []
            dep_resolve(current, res, unres)
            for node in res:
                if "depends" in node.component:
                    for dep in node.component['depends']:
                        if dep not in control_center.nodes:
                            deps.node(dep, color="red")
                            deps.edge(node.comp_name, dep, "missing", color="red")
                        elif node.comp_name is not "master_node":
                            deps.edge(node.comp_name, dep)

    except CircularReferenceException as ex:
        control_center.logger.error("Detected circular dependency reference between %s and %s!" % (ex.node1, ex.node2))
        deps.edge(ex.node1, ex.node2, "circular error", color="red")
        deps.edge(ex.node2, ex.node1, color="red")

    deps.view()


def main():
    """Parse the command line arguments and start hyperion with the specified configuration in the desired mode.

    :return: None
    """

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    parser = argparse.ArgumentParser()

    # Create top level parser
    parser.add_argument("--config", '-c', type=str,
                        default='test.yaml',
                        help="YAML config file. see sample-config.yaml. Default: test.yaml")
    subparsers = parser.add_subparsers(dest="cmd")

    # Create parser for server
    subparser_server = subparsers.add_parser('server', help="Starts hyperion backend")
    subparser_server.add_argument('-p', '--port',
                                  help="Define the tcp port on which the backend will listen for clients. "
                                       "Default: %s" % DEFAULT_TCP_PORT,
                                  metavar="PORT",
                                  type=int,
                                  default=DEFAULT_TCP_PORT)

    # Create parser for the editor command
    subparser_editor = subparsers.add_parser('edit', help="Launches the editor to edit or create new systems and "
                                                          "components")
    # Create parser for the run command
    subparser_cli = subparsers.add_parser('execute', help="initialize the configured system with the executing host as "
                                                          "controlling instance. It offers to run a specific action for"
                                                          " a single component or a list of components")

    subparser_cli.add_argument('-C', '--component', metavar='COMP', help="single component or list of components "
                                                                         "specific action", default='all', nargs='+')

    comp_mutex = subparser_cli.add_mutually_exclusive_group(required=True)

    comp_mutex.add_argument('-l', '--list', help="List all available components", action="store_true")
    comp_mutex.add_argument('-s', '--start', help="start the component", dest='comp_start', action="store_true")
    comp_mutex.add_argument('-k', '--stop', help="Stop the component", dest='comp_stop', action="store_true")
    comp_mutex.add_argument('-c', '--check', help="Check the component", dest='comp_check', action="store_true")
    comp_mutex.add_argument('-L', '--log', help="Show the component log", dest='comp_log', action="store_true")
    comp_mutex.add_argument('-T', '--term', help="Show the component term", dest='comp_term', action="store_true")

    subparser_ui = subparsers.add_parser('ui', help="Launches the setup specified by the --config argument and "
                                                      "start with user interface")

    subparser_ui.add_argument('-p', '--port',
                              help="Specify port to connect to. Defaults to %s" % DEFAULT_TCP_PORT,
                              type=int,
                              default=DEFAULT_TCP_PORT)

    ui_mutex = subparser_ui.add_mutually_exclusive_group(required=False)
    ui_mutex.add_argument('-H', '--host', help="Specify host to connect to. Defaults to localhost", default='localhost')
    ui_mutex.add_argument('--no-socket', help="Start in standalone mode without connecting to a running backend",
                          action="store_true")

    subparser_ui.add_argument('-x', help="Use PyQt gui (requires X server and python-qt4 package)",
                              dest='x_server',
                              action="store_true")

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

    root_logger = logging.getLogger()

    if args.cmd == 'server':
        logger.debug("Starting backend at port: %s" % args.port)
        cc = ControlCenter(args.config, False)
        cc.init()

        s = Server(int(args.port), cc)

    if args.cmd == 'ui':
        logger.debug("Chose ui mode")

        if args.no_socket:
            logger.debug("Entering ui in standalone mode")
            cc = ControlCenter(args.config, False)
            cc.init()
        else:
            logger.debug("Entering ui in socket mode")
            cc = clientInterface.RemoteControllerInterface(args.host, args.port)

        if args.x_server:
            # PyQt
            if gui_enabled:
                logger.debug("Launching GUI runner mode")

                cc = ControlCenter(args.config, True)
                ui = hyperGUI.UiMainWindow()

                signal(SIGINT, SIG_DFL)

                cc.init()
                start_gui(cc, ui)
            else:
                logger.error("To use this feature you need PyQt4! Check the README.md for install instructions")
                sys.exit(1)
        else:
            # Urwid
            if interactive_enabled:
                remove = []
                for handler in root_logger.handlers:
                    if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                        logger.debug("Remove non file stream handlers to disable logging on stdout!")
                        remove.append(handler)
                [root_logger.removeHandler(h) for h in remove]

                cc.cleanup(interactiveCLI.main(cc))
            else:
                logger.error("To use this feature you need urwid! Check the README.md for install instructions")

    if args.cmd == 'edit':
        logger.debug("Launching editor mode")

    if args.cmd == 'execute':
        clilogger = logging.getLogger('EXECUTE-RESPONSE')
        clilogger.setLevel(logging.INFO)
        logger.info("Launching cli mode")

        for handler in root_logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                logger.debug("Setting non file stream handlers to INFO to disable stdout bloating!")
                handler.setLevel(logging.INFO)

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
            if args.comp_log:
                logger.debug("Chose show log of %s" % args.component)
                if len(comps) > 1:
                    logger.warning("The show log option only supports a single component as argument. Only the first is"
                                   "used!")
                cc.show_comp_log(comps[0])
            if args.comp_term:
                logger.debug("Chose show term of %s" % args.component)
                if len(comps) > 1:
                    logger.warning("The show term option only supports a single component as argument. Only the first "
                                   "is used!")
                cc.start_clone_session_and_attach(comps[0])
            cc.cleanup()

    elif args.cmd == 'validate':
        logger.debug("Launching validation mode")
        cc = ControlCenter(args.config)
        if args.visual:
            cc.set_dependencies(False)
            if graph_enabled:
                draw_graph(cc)
            else:
                logger.error("This feature requires graphviz. To use it install hyperion with the GRAPH option "
                             "(pip install -e .['GRAPH'])")
        else:
            cc.set_dependencies(True)
        cc.cleanup()

    elif args.cmd == 'slave':
        logger.debug("Launching slave mode")
        sl = SlaveLauncher(args.config, args.kill, args.check)

        if args.check:
            sl.run_check()
        else:
            sl.init()