import logging
import logging.handlers
import argparse
import sys
import yaml
import time
import lib.util.config as config
from signal import *
from lib.util.setupParser import Loader
from manager import ControlCenter, SlaveManager, ensure_dir, BASE_DIR, clear_log, conf_preprocessing
from lib.util.depTree import dep_resolve
from lib.networking import clientInterface, server
from lib.util.config import TMP_LOG_PATH, DEFAULT_TCP_PORT, FORMAT
from logging.config import fileConfig
from lib.util.exception import *

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

ensure_dir('%s/any.log' % TMP_LOG_PATH)

ensure_dir('%s/localhost/any.log' % TMP_LOG_PATH)
ensure_dir('%s/localhost/client/any.log' % TMP_LOG_PATH)
ensure_dir('%s/localhost/component/any.log' % TMP_LOG_PATH)
ensure_dir('%s/localhost/server/any.log' % TMP_LOG_PATH)
ensure_dir('%s/localhost/slave/any.log' % TMP_LOG_PATH)
ensure_dir('%s/localhost/standalone/any.log' % TMP_LOG_PATH)

ensure_dir('%s/remote/slave/any.log' % TMP_LOG_PATH)

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

    deps = Digraph('Deps', strict=True, graph_attr={'splines': 'polyline', 'outputorder': 'edgesfirst', 'newrank': 'true'})
    deps.graph_attr.update(rankdir='RL')

    subgraphs = {}

    try:
        node = control_center.nodes.get('master_node')

        for current in node.depends_on:

            if not current.component['host'] in subgraphs:
                logging.debug("Creating host subgraph for %s" % current.component['host'])
                subgraphs[current.component['host']] = Digraph(
                    name='cluster_%s' % current.component['host'],
                    graph_attr={'style': 'filled', 'color': 'lightgrey',
                                'label': current.component['host']},
                    node_attr={'style': 'filled', 'color': 'white'}
                )

            subgraphs.get(current.component['host']).node(current.comp_id, label='<%s<BR /><FONT POINT-SIZE="8" color="darkgreen">%s</FONT>>' % tuple(current.comp_id.split('@')),
                                                          _attributes={'style': 'filled',
                                                                       'color': 'white',
                                                                       'shape': 'box'})

            res = []
            unres = []
            dep_resolve(current, res, unres)
            for node in res:

                if not node.component['host'] in subgraphs:
                    logging.debug("Creating host subgraph for %s" % node.component['host'])
                    subgraphs[node.component['host']] = Digraph(
                        name='cluster_%s' % node.component['host'],
                        graph_attr={'style': 'filled', 'color': 'lightgrey',
                                    'label': node.component['host']},
                        node_attr={'style': 'filled', 'color': 'white'}
                    )

                subgraphs.get(node.component['host']).node(node.comp_id,
                                                           label='<%s<BR /><FONT POINT-SIZE="8" color="darkgreen">%s</FONT>>' % tuple(node.comp_id.split('@')),
                                                           _attributes={'style': 'filled',
                                                                        'color': 'white',
                                                                        'shape': 'box'})

                if 'depends' in node.component:
                    for dep in node.component['depends']:

                        if not dep.split('@')[1] in subgraphs:
                            logging.debug("Creating host subgraph for %s" % dep.split('@')[1])
                            subgraphs[dep.split('@')[1]] = Digraph(
                                name='cluster_%s' % dep.split('@')[1],
                                graph_attr={'style': 'filled', 'color': 'lightgrey',
                                            'label': dep.split('@')[1]},
                                node_attr={'style': 'filled', 'color': 'white'}
                            )

                        subgraphs.get(dep.split('@')[1]).node(dep,
                                                              label='<%s<BR /><FONT POINT-SIZE="8" color="darkgreen">%s</FONT>>' %
                                                                    tuple(dep.split('@')),
                                                              _attributes={'style': 'filled',
                                                                           'color': 'white',
                                                                           'shape': 'box'})

                        parent = deps

                        if node.component['host'] == dep.split('@')[1]:
                            parent = subgraphs.get(node.component['host'])

                            logging.debug("%s depends on %s" % (node.comp_id, dep))
                            logging.debug("Host: %s" % node.component['host'])

                        if dep not in control_center.nodes:
                            parent = subgraphs.get(dep.split('@')[1])
                            parent.node(dep,
                                        label='<%s<BR /><FONT POINT-SIZE="8" color="darkgreen">%s</FONT>>' % tuple(dep.split('@')),
                                        color='red',
                                        _attributes={'style': 'filled',
                                                     'color': 'white',
                                                     'shape': 'box'})
                            parent.edge(node.comp_id, dep, 'missing', color='red')

                        elif node.comp_id is not 'master_node':
                            logging.debug("Adding edge in %s" % parent.name)
                            parent.edge(node.comp_id, dep)

    except CircularReferenceException as ex:
        control_center.logger.error('Detected circular dependency reference between %s and %s!' % (ex.node1, ex.node2))
        deps.edge(ex.node1, ex.node2, 'circular error', color='red')
        deps.edge(ex.node2, ex.node1, color='red')

    for subgraph in subgraphs:
        deps.subgraph(subgraphs.get(subgraph))

    logging.debug(deps)

    deps.view()


def main():
    """Parse the command line arguments and start hyperion with the specified configuration in the desired mode.

    :return: None
    """

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    parser = argparse.ArgumentParser()

    # Create top level parser
    parser.add_argument('--config', '-c', type=str,
                        help='YAML config file. see sample-config.yaml.')
    subparsers = parser.add_subparsers(dest='cmd')

    # Create parser for server
    subparser_server = subparsers.add_parser('server', help='Starts hyperion backend')
    subparser_server.add_argument('-p', '--port',
                                  help='Define the tcp port on which the backend will listen for clients. '
                                       'Default: %s' % DEFAULT_TCP_PORT,
                                  metavar='PORT',
                                  type=int,
                                  default=DEFAULT_TCP_PORT)

    # Create parser for the editor command
    subparser_editor = subparsers.add_parser('edit', help='Launches the editor to edit or create new systems and '
                                                          'components')
    # Create parser for the run command
    subparser_cli = subparsers.add_parser('execute', help='initialize the configured system with the executing host as '
                                                          'controlling instance. It offers to run a specific action for'
                                                          ' a single component or a list of components')

    subparser_cli.add_argument('-C', '--component', metavar='COMP', help='single component or list of components '
                                                                         'specific action', default='all', nargs='+')
    subparser_cli.add_argument(
        '-f',
        '--force-mode',
        help='set force mode for component start (only makes sense combined with --start flag)',
        dest='force_mode',
        action='store_true'
    )

    comp_mutex = subparser_cli.add_mutually_exclusive_group(required=True)

    comp_mutex.add_argument('-l', '--list', help='List all available components', action='store_true')
    comp_mutex.add_argument('-s', '--start', help='start the component', dest='comp_start', action='store_true')
    comp_mutex.add_argument('-k', '--stop', help='Stop the component', dest='comp_stop', action='store_true')
    comp_mutex.add_argument('-c', '--check', help='Check the component', dest='comp_check', action='store_true')
    comp_mutex.add_argument('-L', '--log', help='Show the component log', dest='comp_log', action='store_true')
    comp_mutex.add_argument('-T', '--term', help='Show the component term', dest='comp_term', action='store_true')

    subparser_ui = subparsers.add_parser('ui', help='Launches the setup specified by the --config argument and '
                                                    'start with user interface')

    subparser_ui.add_argument('-p', '--port',
                              help='Specify port to connect to. Defaults to %s' % DEFAULT_TCP_PORT,
                              type=int,
                              default=DEFAULT_TCP_PORT)

    ui_mutex = subparser_ui.add_mutually_exclusive_group(required=False)
    ui_mutex.add_argument('-H', '--host', help='Specify host to connect to. Defaults to localhost', default='localhost')
    ui_mutex.add_argument('--no-socket', help='Start in standalone mode without connecting to a running backend',
                          action='store_true')

    subparser_ui.add_argument(
        '-x',
        help='Use PyQt gui (requires X server and python-qt4 package)',
        dest='x_server',
        action='store_true'
    )

    # Create parser for validator
    subparser_val = subparsers.add_parser('validate', help='Validate the setup specified by the --config argument')
    subparser_val.add_argument('--visual', help='Generate and show a graph image', action='store_true')

    subparser_remote = subparsers.add_parser('slave', help='Run a component locally without controlling it. The '
                                                           'control is taken care of the remote master invoking '
                                                           'this command.\nIf run with the --kill flag, the '
                                                           'passed component will be killed')

    subparser_remote.add_argument('-p', '--port',
                                  help='specify port of the master server to connect to',
                                  type=int, required=True)

    subparser_remote.add_argument('-H', '--host',
                                  help='specify master server hostname to connect to',
                                  required=True)

    args = parser.parse_args()
    logger.debug(args)

    root_logger = logging.getLogger()
    log_formatter = logging.Formatter(FORMAT)
    log_name = ''

    if args.config:
        try:
            with open(args.config) as data_file:
                tmp_config = yaml.load(data_file, Loader)
                conf_name = tmp_config['name']
                if conf_name.find(' ') != -1:
                    logger.critical('Your config name contains at least one space, which is not allowed! Change it')
                    sys.exit(config.ExitStatus.ERRONEUS_CONFIG)
                log_name = '%s' % conf_name
        except IOError:
            logger.critical("No config file at '%s' found" % args.config)
            sys.exit(config.ExitStatus.CONFIG_NOT_FOUND)

    if args.cmd == 'server':
        log_file_path = '%s/localhost/server/%s.log' % (TMP_LOG_PATH, log_name)
        clear_log(log_file_path, log_name)
        handler = logging.handlers.RotatingFileHandler(log_file_path, 'w')

        handler.setFormatter(log_formatter)
        root_logger.addHandler(handler)

        sms = server.SlaveManagementServer()

        logger.debug('Starting backend at port: %s' % args.port)
        cc = ControlCenter(args.config, True, slave_server=sms)
        cc.init()

        s = server.Server(int(args.port), cc)
        sys.exit(config.ExitStatus.FINE)

    if args.cmd == 'ui':
        logger.debug('Chose ui mode')

        if args.x_server:
            logger.critical("PyQt gui is a work in progress and currently disabled!")
            sys.exit(0)

        if args.no_socket:

            if not args.config:
                logger.critical("If you start in standalone mode you need to supply a configuration!")
                sys.exit(config.ExitStatus.MISSING_CONFIG)

            log_file_path = '%s/localhost/standalone/%s.log' % (TMP_LOG_PATH, time.strftime("%H-%M-%S"))
            handler = logging.handlers.RotatingFileHandler(log_file_path, 'w')

            handler.setFormatter(log_formatter)
            root_logger.addHandler(handler)
            logger.debug('Entering ui in standalone mode')
            sms = server.SlaveManagementServer()
            cc = ControlCenter(args.config, True, slave_server=sms)
            cc.init()
        else:
            log_file_path = '%s/localhost/client/%s.log' % (TMP_LOG_PATH, time.strftime("%H-%M-%S"))
            clear_log(log_file_path, log_name)
            handler = logging.handlers.RotatingFileHandler(log_file_path, 'w')

            handler.setFormatter(log_formatter)
            root_logger.addHandler(handler)

            logger.debug('Entering ui in socket mode')

            cc = clientInterface.RemoteControllerInterface(args.host, args.port)

        if args.x_server:
            # PyQt
            if gui_enabled:
                logger.debug('Launching GUI runner mode')

                ui = hyperGUI.UiMainWindow()
                signal(SIGINT, SIG_DFL)

                start_gui(cc, ui)
            else:
                logger.error('To use this feature you need PyQt4! Check the README.md for install instructions')
                cc.cleanup(False, config.ExitStatus.MISSING_PYQT_INSTALL)
        else:
            # Urwid
            if interactive_enabled:
                remove = []
                for handler in root_logger.handlers:
                    if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                        logger.debug('Remove non file stream handlers to disable logging on stdout!')
                        remove.append(handler)
                [root_logger.removeHandler(h) for h in remove]

                cc.cleanup(interactiveCLI.main(cc, log_file_path))
            else:
                logger.error('To use this feature you need urwid! Check the README.md for install instructions')

    if args.cmd == 'edit':
        logger.debug('Launching editor mode')

    if args.cmd == 'execute':
        clilogger = logging.getLogger('EXECUTE-RESPONSE')
        clilogger.setLevel(logging.INFO)
        logger.info('Launching cli mode')

        for handler in root_logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                logger.debug('Setting non file stream handlers to INFO to disable stdout bloating!')
                handler.setLevel(logging.INFO)

        log_file_path = '%s/localhost/server/%s.log' % (TMP_LOG_PATH, log_name)
        clear_log(log_file_path, log_name)
        handler = logging.handlers.RotatingFileHandler(log_file_path, 'w')

        handler.setFormatter(log_formatter)
        root_logger.addHandler(handler)

        sms = server.SlaveManagementServer()
        cc = ControlCenter(args.config, slave_server=sms)
        cc.init()

        if args.list:
            logger.debug('Chose --list option')
            if args.component != 'all':
                logger.warning('Specifying a component with the -C option is useless in combination with the '
                               '--list option!')
            clilogger.info('List of all components included in the current configuration:\t%s' % cc.list_components())
        else:
            logger.debug('Chose comp specific operation:')
            comps = args.component
            if comps == 'all':
                comps = cc.list_components()

            if args.comp_start:
                logger.debug('Chose start %s' % args.component)
                for comp in comps:
                    cc.start_by_cli(comp, args.force_mode)
            if args.comp_stop:
                logger.debug('Chose stop %s' % args.component)
                for comp in comps:
                    cc.stop_by_cli(comp)
            if args.comp_check:
                logger.debug('Chose check %s' % args.component)
                for comp in comps:
                    cc.check_by_cli(comp)
            if args.comp_log:
                logger.debug('Chose show log of %s' % args.component)
                if len(comps) > 1:
                    logger.warning('The show log option only supports a single component as argument. Only the first is'
                                   'used!')
                cc.show_comp_log(comps[0])
            if args.comp_term:
                logger.debug('Chose show term of %s' % args.component)
                if len(comps) > 1:
                    logger.warning('The show term option only supports a single component as argument. Only the first '
                                   'is used!')
                cc.start_clone_session_and_attach(comps[0])
            cc.cleanup()

    elif args.cmd == 'validate':
        logger.debug('Launching validation mode')
        cc = ControlCenter(args.config)
        conf_preprocessing(cc.config, cc.custom_env_path)

        if args.visual:
            try:
                cc.set_dependencies()
            except UnmetDependenciesException or CircularReferenceException:
                pass

            if graph_enabled:
                draw_graph(cc)
            else:
                logger.error('This feature requires graphviz. To use it install hyperion with the GRAPH option '
                             "(pip install -e .['GRAPH'])")
        else:
            try:
                cc.set_dependencies()
            except UnmetDependenciesException or CircularReferenceException:
                cc.cleanup(status=config.ExitStatus.DEPENDENCY_RESOLUTION_ERROR)
        cc.cleanup()

    elif args.cmd == 'slave':
        log_file_path = '%s/localhost/slave/%s.log' % (TMP_LOG_PATH, log_name)
        clear_log(log_file_path, log_name)
        handler = logging.handlers.RotatingFileHandler(log_file_path, 'w')

        handler.setFormatter(log_formatter)

        socket_handler = logging.handlers.SocketHandler(args.host, args.port)
        socket_handler.setLevel(logging.INFO)

        memory_handler = logging.handlers.MemoryHandler(
            capacity=1024*4000,
            flushLevel=logging.CRITICAL,
            target=socket_handler
        )

        root_logger.addHandler(handler)
        root_logger.addHandler(socket_handler)
        root_logger.addHandler(memory_handler)

        logger.debug('Launching slave mode')
        slc = SlaveManager(args.config)
        clientInterface.RemoteSlaveInterface(args.host, args.port, slc)

        logger.debug('Flushing memory handler!')
        memory_handler.close()
        sys.exit(config.ExitStatus.FINE)
