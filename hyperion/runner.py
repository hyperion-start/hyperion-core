import logging
import argparse
import sys
from manager import ControlCenter, SlaveLauncher
from lib.util.depTree import CircularReferenceException, dep_resolve

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
    print("Found urwid. Interactive CLI mode is available")
    interactive_enabled = True


###################
# GUI
###################
def start_gui(control_center):
    app = QtGui.QApplication(sys.argv)
    main_window = QtGui.QMainWindow()
    ui = hyperGUI.UiMainWindow()
    ui.ui_init(main_window, control_center)
    main_window.show()
    app.exec_()


###################
# Visualisation
###################
def draw_graph(control_center):
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

    comp_mutex.add_argument('-I', '--interactive', help="Start interactive cli mode", action="store_true")
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

        cc = ControlCenter(args.config, args.interactive)
        cc.init()

        if args.interactive:
            logger.debug("Chose interactive mode")
            if interactive_enabled:
                interactiveCLI.main(cc)
                cc.cleanup()
            else:
                clilogger.error("To use this feature you need urwid! Check the README.md for install instructions")
        elif args.list:
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
            cc.cleanup()

    elif args.cmd == 'gui':
        if gui_enabled:
            logger.debug("Launching GUI runner mode")

            cc = ControlCenter(args.config, True)
            cc.init()
            start_gui(cc)
            cc.cleanup()
        else:
            logger.error("To use this feature you need PyQt4! Check the README.md for install instructions")
            sys.exit(1)

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