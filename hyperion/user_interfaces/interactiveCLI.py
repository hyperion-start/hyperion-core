import urwid
import threading
import re
from os.path import isfile
import hyperion.manager
import hyperion.lib.util.exception as exceptions
import hyperion.lib.util.events as events

from hyperion.lib.monitoring.threads import *


is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as queue
else:
    import queue as queue


class LogTextWalker(urwid.SimpleFocusListWalker):
    """SimpleFocusListWalker-compatible class for reading file contents."""

    def set_modified_callback(self, callback):
        pass

    def __init__(self, name, title):
        self.lines = []
        self.keep_reading = True
        super(LogTextWalker, self).__init__(self.lines)

        self.file_name = name
        self.file = open(name)
        self.focus = 0
        self.end = False
        self.read_file()
        self.title = title

    def get_focus(self):
        return self._get_at_pos(self.focus)

    def set_focus(self, focus):
        self.focus = focus
        self._modified()

    def get_next(self, start_from):
        return self._get_at_pos(start_from + 1)

    def get_prev(self, start_from):
        return self._get_at_pos(start_from - 1)

    def read_file(self):

        next_line = None
        while self.keep_reading:
            try:
                next_line = self.file.readline()
            except IOError as e:
                if e.errno == 107:
                    logging.getLogger(__name__).error(
                        "File '%s' does not exists anymore and can't be read. Probably was connected over sshfs and"
                        " connection was lost" % self.file_name
                    )
                else:
                    logging.getLogger(__name__).error("Unknown IO error while reading file '%s'" % self.file_name)
                self.keep_reading = False

            if not next_line or next_line[-1:] != '\n':
                # no newline on last line of file
                return
            # Strip '\n' from next line
            next_line = next_line[:-1]

            # Remove ANSI escape sequences from tty stdout
            ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
            next_line = ansi_escape.sub('', next_line)

            self.lines.append(urwid.Text(next_line))
            self.append(urwid.Text(next_line))

    def _get_at_pos(self, pos):
        """Return a widget for the line number passed."""

        if pos < 0:
            # line 0 is the start of the file, no more above
            return None, None

        if len(self.lines) > pos:
            # we have that line so return it
            return self.lines[pos], pos

        assert pos == len(self.lines), "out of order request?"

        # File end
        return None, None


class SimpleButton(urwid.Button):
    def __init__(self, caption, callback=None, user_data=None):
        super(SimpleButton, self).__init__("")
        if callback:
            urwid.connect_signal(self, 'click', callback, user_data)
        label = urwid.SelectableIcon(caption, 0)
        label.set_align_mode('center')
        self._w = urwid.AttrMap(label, None, 'simple_button')


class StateController(object):
    """Intermediate interface class that constructs a urwid UI connected to the core application."""

    def __init__(self, cc, event_queue, log_file_path):
        """Initialize StateController constructing the urwid UI.

        :param cc: Reference to core application
        :type cc: hyperion.ControlCenter
        """

        self.cc = cc
        self.selected_group = None
        self.groups = {}
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.event_queue = event_queue
        self.log_viewer = LogTextWalker(log_file_path, "Main")
        self.tail_log = True
        self.states = {}
        self.host_stats = None
        self.log_hidden = False
        self.force_mode = False

        self.comp_log_map = {}

        header_text = urwid.Text(u'%s' % cc.config['name'], align='center')
        header = urwid.Pile([urwid.Divider(), urwid.AttrMap(header_text, 'titlebar')])

        self.load_groups_from_config()

        self.radio_button_log_group = []
        group_col = self.group_col = urwid.Columns([], 1)
        components_pile = self.components_pile = urwid.Pile([])
        host_pile = self.host_pile = urwid.Pile([
            urwid.Columns([
                urwid.AttrMap(SimpleButton('Host 1'), 'host', focus_map='reversed'),
                urwid.Text('16', align='center'),
                urwid.Text('100%', align='center'),
                urwid.Text('100%', align='center')
            ], 1),

            urwid.Columns([
                urwid.AttrMap(SimpleButton('Host 2'), 'host', focus_map='reversed'),
                urwid.Text('1.6', align='center'),
                urwid.Text('100%', align='center'),
                urwid.Text('100%', align='center')
            ], 1),

            urwid.Columns([
                urwid.AttrMap(SimpleButton('Host 3'), 'host', focus_map='reversed'),
                urwid.Text('4', align='center'),
                urwid.Text('100%', align='center'),
                urwid.Text('100%', align='center')
            ], 1)
        ])

        self.additional_content_grid = urwid.GridFlow([
            urwid.Columns([
                urwid.Pile([
                    urwid.LineBox(urwid.Pile([
                        urwid.Columns([
                            SimpleButton('Start', self.handle_start_all),
                            SimpleButton('Stop', self.handle_stop_all),
                            SimpleButton('Check', self.handle_check_all),
                            SimpleButton('Reload Config', self.handle_reload_config)
                        ], 1)
                    ]), 'All Components'),

                    urwid.LineBox(
                        urwid.Pile([
                            urwid.AttrMap(urwid.Text('Host Stats', align='center'), 'titlebar'),
                            urwid.Divider(),
                            urwid.Columns([
                                urwid.AttrMap(urwid.Text('Hostname', align='center'), 'important'),
                                urwid.AttrMap(urwid.Text('Load AVG', align='center'), 'important'),
                                urwid.AttrMap(urwid.Text('CPU', align='center'), 'important'),
                                urwid.AttrMap(urwid.Text('MEM', align='center'), 'important')
                            ], 1),
                            host_pile
                        ])
                    )
                ]),
            ], 1),
        ],
            80, 3, 1, 'center'
        )

        blank = urwid.Divider()
        list_box_contents = [
            blank,
            urwid.Divider('='),
            group_col,
            urwid.Divider('='),
            urwid.Padding(urwid.LineBox(components_pile), left=2, right=2),
            self.additional_content_grid,
        ]

        self.logger_section = urwid.Pile([
            urwid.Divider(),
            urwid.Padding(urwid.Divider('#'), left=10, right=10),
            urwid.Divider(),
            urwid.AttrMap(
                urwid.LineBox(urwid.BoxAdapter(urwid.ListBox(self.log_viewer), 10), 'Hyperion Log'),
                None,
                'simple_button'),
        ])

        self.log_placeholder = urwid.WidgetPlaceholder(self.logger_section)

        menu = urwid.Pile([
            self.log_placeholder,
            urwid.Text([
                u'Press (', ('refresh button', u'K'), u') to show or hide Hyperion log | ',
                u'Press (', ('refresh button', u'L'), u') to jump into or out of Hyperion log | ',
                u'Press (', ('quit button', u'Q'), u') to quit.'
            ])
        ])

        self.fetch_group_items()
        self.setup_component_states()
        self.fetch_components()
        self.fetch_host_items()

        self.content_walker = urwid.SimpleListWalker(list_box_contents)

        main_body = self.main_body = urwid.ListBox(self.content_walker)
        self.layout = urwid.Frame(header=header, body=main_body, footer=menu)

        help = [
            urwid.Divider('='),
            urwid.Text(('titlebar', u'Help Menu'), "center"),
            urwid.Divider('='),
            urwid.Divider(),
            urwid.Text([u'Navigate through menus by using the ', ('host', u'arrow keys')], "center"),
            urwid.Divider(),
            urwid.Text([u'Click buttons with ', ('host', u'Enter'), u', ', ('host', u'Space'),
                        u' or with your ', ('host', u'Mouse')], "center"),
            urwid.Divider(),
            urwid.Text([u'Jump to or out of the application log by pressing ', ('host', u'L')], "center"),
            urwid.Divider(),
            urwid.Text([u'Press ', ('host', u'K'), u' to hide or un-hide the application log'], "center"),
            urwid.Divider(),
            urwid.Text([u'When focussing a component log press ', ('host', u'C'), u' to close it'], "center"),
            urwid.Divider(),
            urwid.Text([u'Press ', ('host', u'F'), u' to toggle force mode (if active component start is tried even if '
                                                   u'dependencies failed)'], "center"),
            urwid.Divider(),
            urwid.Text([u'Press ', ('host', u'H'), u' to show this help and ',
                        ('host', u'Esc'), u' to dismiss it'], "center"),
            urwid.Divider(),
            urwid.Text([u'Press ', ('quit button', u'Q'), u' to close the application'], "center"),
        ]

        help_box = urwid.AttrMap(urwid.LineBox(urwid.ListBox(urwid.SimpleListWalker(help))), 'popup')
        self.help_overlay = urwid.Overlay(help_box, self.layout, align='center', width=('relative', 60),
                                          valign='middle', height=('relative', 60))

        shutdown_box = urwid.AttrMap(
            urwid.LineBox(
                urwid.ListBox(urwid.SimpleFocusListWalker([
                    urwid.Divider('='),
                    urwid.Text(('titlebar', u'Shutdown Menu'), "center"),
                    urwid.Divider('='),
                    urwid.Divider(),
                    urwid.Text('Do you want to close all running processes?', "center"),
                    urwid.Columns([
                        urwid.AttrMap(SimpleButton('Yes', self.handle_shutdown, True), 'quit button'),
                        urwid.AttrMap(SimpleButton('No', self.handle_shutdown, False), 'host'),
                        SimpleButton('Cancel', self.dismiss_popup)
                    ])
                ]))
            ),
            'popup'
        )

        self.shutdown_overlay = urwid.Overlay(shutdown_box, self.layout, align='center', width=('relative', 60),
                                          valign='middle', height=('relative', 60))

    def load_groups_from_config(self):
        for g in self.cc.config['groups']:
            self.groups[g['name']] = g
        self.groups['All'] = ({'name': 'All'})

    def setup_component_states(self):
        for grp in self.groups:
            group = self.groups[grp]
            if group['name'] != 'All':
                for comp in group['components']:
                    self.states[comp['id']] = urwid.Text(
                        "state: %s" % config.SHORT_STATE_DESCRIPTION.get(config.CheckState.UNKNOWN))

    def fetch_host_items(self):
        """Get all hosts to display in the UI.

        :return None
        """
        hosts = []
        for host in self.cc.host_states:
            host_object = SimpleButton(host, self.handle_host_clicked, user_data=host)
            state = self.cc.host_states[host]
            if state == config.HostState.CONNECTED:
                host_object = urwid.AttrMap(host_object, 'host', focus_map='reversed')
            elif state == config.HostState.SSH_ONLY:
                host_object = urwid.AttrMap(host_object, 'partly_available_host', focus_map='reversed')
            elif state == config.HostState.DISCONNECTED:
                host_object = urwid.AttrMap(host_object, 'unavailable_host', focus_map='reversed')

            self.host_stats = urwid.Columns([
                host_object,
                urwid.Text('4', align='center'),
                urwid.Text('100%', align='center'),
                urwid.Text('100%', align='center')
            ], 1)
            hosts.append((self.host_stats, ('weight', 1)))

        self.host_pile.contents[:] = hosts

    def fetch_group_items(self):
        """Make a button for every group defined in the configuration file and add an 'all' group.

        :return: None
        """
        groups = []
        for g in self.cc.config['groups']:

            if not self.selected_group:
                self.selected_group = g['name']

            grp = SimpleButton(g['name'], self.change_group, g['name'])
            if g['name'] == self.selected_group:
                grp = urwid.AttrMap(grp, 'group_selected')
            else:
                grp = urwid.AttrMap(grp, 'group')
            groups.append((grp, self.group_col.options()))

        all_group = SimpleButton(u'All', self.change_group, 'All')
        if self.selected_group == 'All':
            all_group = urwid.AttrMap(all_group, 'group_selected')
        else:
            all_group = urwid.AttrMap(all_group, 'group')
        groups.append((all_group, self.group_col.options()))

        self.group_col._set_contents(groups)

    def change_group(self, button, group):
        """Change the currently selected group.

        :param group: Group that got selected
        :type group: str
        :return: None
        """

        self.selected_group = group
        self.fetch_group_items()
        self.fetch_components()

    def fetch_components(self):
        """Reloads components to display and triggers a group status display refresh.

        :return: None
        """

        group = self.groups[self.selected_group]
        comps = []
        if group['name'] != 'All':
            for c in group['components']:

                if c['id'] in self.states:
                    state = self.states[c['id']]
                else:
                    self.states[c['id']] = state = urwid.Text(
                        "state: %s" % config.SHORT_STATE_DESCRIPTION.get(config.CheckState.UNKNOWN))

                comps.append((urwid.Columns([
                    urwid.AttrMap(SimpleButton(c['id']), 'important', focus_map='reversed'),
                    state,
                    SimpleButton('Start', self.handle_start, c),
                    SimpleButton('Stop', self.handle_stop, c),
                    SimpleButton('Check', self.handle_check, c),
                    SimpleButton('Toggle Log', self.handle_log, c),
                ], 1), ('weight', 1)))

        else:
            for grp in self.groups:
                group = self.groups[grp]
                if group['name'] != 'All':
                    for c in group['components']:

                        if c['id'] in self.states:
                            state = self.states[c['id']]
                        else:
                            self.states[c['id']] = state = urwid.Text(
                                "state: %s" % config.SHORT_STATE_DESCRIPTION.get(config.CheckState.UNKNOWN))

                        comps.append((urwid.Columns([
                            urwid.AttrMap(SimpleButton(c['id']), 'important',
                                          focus_map='reversed'),
                            state,
                            SimpleButton('Start', self.handle_start, c),
                            SimpleButton('Stop', self.handle_stop, c),
                            SimpleButton('Check', self.handle_check, c),
                            SimpleButton('Toggle Log', self.handle_log, c),
                        ], 1), ('weight', 1)))

        self.components_pile.contents[:] = comps

    def handle_input(self, key):
        """Handle user input that was not handled by active urwid components.

        :param key: User input to process
        :type key: str
        :return: None
        """

        if key == 'F' or key == 'f':
            header_text = urwid.Text(u'%s' % self.cc.config['name'], align='center')
            if self.force_mode:
                header = urwid.Pile([
                    urwid.Divider(),
                    urwid.AttrMap(header_text, 'titlebar')
                ])
            else:
                header = urwid.Pile([
                    urwid.Divider(), urwid.AttrMap(header_text, 'titlebar'),
                    urwid.AttrMap(urwid.Text(u'FORCE MODE ACTIVE', align='center'), 'force_mode')
                ])
            self.force_mode = not self.force_mode
            self.layout.header = header

        if key == 'Q' or key == 'q':
            main_loop.widget = urwid.Frame(self.shutdown_overlay)

        if key == 'esc':
            self.dismiss_popup()

        if key == 'K' or key == 'k':
            if self.log_hidden:
                self.log_placeholder.original_widget = self.logger_section
                self.log_hidden = False
            else:
                if not self.tail_log:
                    self.layout.focus_position = 'body'
                    self.tail_log = True
                self.log_placeholder.original_widget = urwid.Pile([])
                self.log_hidden = True

        if key == 'C' or key == 'c':
            selection, index = self.content_walker.get_focus()
            if isinstance(selection, urwid.GridFlow):
                index = self.additional_content_grid.focus_position
                if index > 0:  # Not 'All Components/Host Stats' Pile in Grid flow
                    # Grants LogTextWalker
                    comp_id = self.additional_content_grid[index].body.title
                    log = self.comp_log_map[comp_id]
                    self.additional_content_grid.contents.remove((log, self.additional_content_grid.options()))
                    self.comp_log_map[comp_id] = None

        if key == 'L' or key == 'l':
            if not self.log_hidden:
                if self.tail_log:
                    self.layout.focus_position = 'footer'
                    self.tail_log = False
                else:
                    self.layout.focus_position = 'body'
                    self.tail_log = True

        if key == 'H' or key == 'h':
            main_loop.widget = urwid.Frame(self.help_overlay)

    def handle_reload_config(self, button):
        urwid.AttrMap(button, 'group_selected')
        self.logger.info("Clicked reload config")
        threading.Thread(
            target=self.cc.reload_config, name='reload_config',
        ).start()

    def handle_start_all(self, button):
        urwid.AttrMap(button, 'group_selected')
        self.logger.info("Clicked start all")
        threading.Thread(
            target=self.cc.start_all, args=[self.force_mode], name='start_all',
        ).start()

    def handle_start(self, button, comp):
        self.logger.info("Clicked start %s" % comp['id'])
        threading.Thread(
            target=self.cc.start_component, args=[comp, self.force_mode],
            name='start_comp_%s' % comp['id'],
        ).start()

    def handle_stop_all(self, button):
        self.logger.info("Clicked stop all")
        threading.Thread(
            target=self.cc.stop_all, args=[],
            name='stop_comp_all',
        ).start()

    def handle_stop(self, button, comp):
        self.logger.info("Clicked stop %s" % comp['id'])
        threading.Thread(
            target=self.stop_component, args=[comp],
            name='stop_comp_%s' % comp['id'],
        ).start()

    def handle_host_clicked(self, button, host):
        self.logger.info("Clicked host '%s'" % host)
        state = self.cc.host_states[host]
        if state and state == config.HostState.CONNECTED:
            if self.cc.is_localhost(host):
                server_file_path = '%s/localhost/server/%s.log' % (config.TMP_LOG_PATH, self.cc.config['name'])
                slave_file_path = '%s/localhost/slave/%s.log' % (config.TMP_LOG_PATH, self.cc.config['name'])
            else:
                server_file_path = '%s/%s/server/%s.log' % (config.TMP_LOG_PATH, host, self.cc.config['name'])
                slave_file_path = '%s/%s/slave/%s.log' % (config.TMP_LOG_PATH, host, self.cc.config['name'])

            if isfile(server_file_path):
                self.show_log_file(server_file_path, 'Server on %s' % host)
            elif isfile(slave_file_path):
                self.show_log_file(slave_file_path, 'Slave on %s' % host)
            else:
                self.logger.error("Neither of the following paths exists! \n%s\n%s" % (server_file_path, slave_file_path))
        else:
            threading.Thread(
                target=self.cc.reconnect_with_host, args=[host],
                name='reconnect_%s' % host,
            ).start()

    def stop_component(self, comp):
        """Stop component and run a component check right afterwards to update the ui status.

        :param comp: Component that will be stopped
        :type comp: dict
        :return: None
        """
        self.cc.stop_component(comp)
        self.cc.check_component(comp)

    def handle_check_all(self, button):
        for grp in self.groups:
            group = self.groups[grp]
            if group['name'] != 'All':
                for comp in group['components']:
                    threading.Thread(
                        target=self.handle_check, args=[None, comp],
                        name='check_comp_%s' % comp['id'],
                    ).start()

    def handle_check(self, button, comp):
        self.logger.info("Clicked check %s" % comp['id'])
        threading.Thread(
            target=self.cc.check_component, args=[comp],
            name='check_comp_%s' % comp['id'],
        ).start()

    def handle_log(self, button, comp):
        self.logger.info("Clicked log %s" % comp['id'])

        try:
            on_localhost = self.cc.run_on_localhost(comp)
        except exceptions.HostUnknownException:
            self.logger.warn("Host '%s' is unknown and therefore not reachable!" % comp['host'])
            return

        if on_localhost:
            local_file_path = '%s/localhost/component/%s/latest.log' % (config.TMP_LOG_PATH, comp['id'])
        else:
            local_file_path = '%s/%s/component/%s/latest.log' % (config.TMP_LOG_PATH, comp['host'], comp['id'])

        self.logger.debug("Filepath: %s" % local_file_path)
        self.show_log_file(local_file_path, comp['id'])

    def show_log_file(self, log_path, title):
        if isfile(log_path):
            log = self.comp_log_map.get(title, None)
            if log:
                self.logger.info("Closing '%s' log" % title)
                self.additional_content_grid.contents.remove((log, self.additional_content_grid.options()))
                self.comp_log_map[title] = None
            else:
                self.logger.info("Opening '%s' log" % title)
                log = urwid.AttrMap(
                    urwid.LineBox(urwid.BoxAdapter(
                        urwid.ListBox(
                            LogTextWalker(log_path, title)),
                            10
                        ), '%s Log' % title
                    ),
                    None,
                    focus_map='simple_button'
                )
                self.comp_log_map[title] = log
                self.additional_content_grid.contents.append((log, self.additional_content_grid.options()))
        else:
            self.logger.error("Log file '%s' does not exist!" % log_path)

    def handle_shutdown(self, button, full=False):
        self.full_shutdown = full
        raise urwid.ExitMainLoop()

    def dismiss_popup(self, button=None, user_data=None):
        main_loop.widget = self.layout

    def start_report_popup(self, event):
        """Generate and display a start report popup.

        :param event: Start report event containing information about failed components
        :type event: events.StartReportEvent
        :return: None
        """
        failed = False
        start_all_popup_content = [
            urwid.Divider('='),
            urwid.Text(('titlebar', u'Start %s Report' % event.component), "center"),
            urwid.Divider('='),
        ]

        fail_popup_content = []
        for comp_name in event.failed_comps:
            failed = True
            fail_popup_content.extend([
                urwid.Divider(),
                urwid.Text(u'%s: %s' % (
                    comp_name,
                    config.STATE_DESCRIPTION.get(event.failed_comps.get(comp_name))
                ))
            ])

        if failed:
            start_all_popup_content.extend([
                urwid.Divider(),
                urwid.AttrMap(urwid.Text('Starting %s failed!' % event.component, "center"), 'simple_button'),
                urwid.Divider()
            ])
            start_all_popup_content.extend(fail_popup_content)
        else:
            start_all_popup_content.extend([
                urwid.Divider(),
                urwid.AttrMap(urwid.Text('Starting %s complete!' % event.component, "center"), 'simple_button'),
                urwid.Divider()
            ])

        start_all_box = urwid.AttrMap(
            urwid.LineBox(
                urwid.ListBox(urwid.SimpleFocusListWalker(
                    start_all_popup_content + [SimpleButton('Close', self.dismiss_popup)])
                )
            ),
            'popup'
        )

        start_all_overlay = urwid.Overlay(start_all_box, self.layout, align='center', width=('relative', 60),
                                          valign='middle', height=('relative', 60))
        main_loop.widget = urwid.Frame(start_all_overlay)


def main(cc, log_file_path):
    """Creates a state controller and starts urwid.

    :param cc: Reference to the core application
    :type cc: hyperion.ControlCenter
    :param log_file_path: Path of the file this logger logs to
    :type log_file_path: str
    :return: None
    """
    event_queue = queue.Queue()
    cli_menu = StateController(cc, event_queue, log_file_path)
    cc.add_subscriber(event_queue)

    palette = [
        ('titlebar', 'dark red', ''),
        ('simple_button', 'light gray,blink', 'black'),
        ('refresh button', 'dark green,bold', ''),
        ('reversed', 'standout', ''),
        ('quit button', 'dark red', ''),
        ('button', 'black', 'light gray'),
        ('button_select', 'light gray', 'black'),
        ('group', 'dark blue', "black"),
        ('group_selected', 'white', 'black'),
        ('headers', 'white,bold', ''),
        ('host', 'dark green', ''),
        ('unavailable_host', 'dark red', ''),
        ('partly_available_host', 'brown', ''),
        ('important', 'dark blue', 'black', ('standout', 'underline')),
        ('selected', 'white', 'dark blue'),
        ('deselected', 'white', 'light gray'),
        ('popup', '', 'black'),
        # CheckState stuff
        ('stopped', 'white', 'dark red'),
        ('running', 'white', 'dark green'),
        ('other', 'white', 'brown'),
        ('force_mode', 'white', 'dark red'),
    ]

    global main_loop
    main_loop = urwid.MainLoop(cli_menu.layout, palette, unhandled_input=cli_menu.handle_input, pop_ups=True)
    main_loop.set_alarm_in(0, refresh, cli_menu)
    main_loop.run()
    return cli_menu.full_shutdown


def refresh(_loop, state_controller, _data=None):
    """Update Hyperion logger and set an automatic trigger for .5 seconds.

    :param _loop: Urwid main loop
    :param _data:
    :param state_controller: Reference to UI manager
    :type state_controller: StateController
    :return: None
    """

    logger = logging.getLogger(__name__)
    if state_controller.tail_log:
        state_controller.log_viewer.read_file()
        state_controller.log_viewer.set_focus(len(state_controller.log_viewer.lines)-1)

    # Get selected log, if one is selected
    selection, index = state_controller.content_walker.get_focus()
    selected = None
    if isinstance(selection, urwid.GridFlow):
        index = state_controller.additional_content_grid.focus_position
        if index > 0: # Not 'All Components/Host Stats' Pile in Grid flow
            # Grants LogTextWalker
            selected = state_controller.additional_content_grid[index].body

    for log_name in state_controller.comp_log_map:
        widget = state_controller.comp_log_map.get(log_name)
        if widget:
            # AttrMap -> LineBox -> BoxAdapter -> ListBox -> LogTextWalker
            log = widget.original_widget.original_widget.original_widget.body
            log.read_file()
            if log is not selected:
                log.set_focus(len(log.lines)-1)

    event_queue = state_controller.event_queue
    while not event_queue.empty():
        event = event_queue.get_nowait()

        logger.debug("Got event: %s" % event)

        if isinstance(event, events.CheckEvent):
            logger.debug("Check event - comp %s; state %s" % (event.comp_id, event.check_state))
            state_controller.states[event.comp_id].set_text([
                "state: ",
                (
                    '%s' % config.URWID_ATTRIBUTE_FOR_STATE.get(config.CheckState(event.check_state)),
                    "%s" % config.SHORT_STATE_DESCRIPTION.get(config.CheckState(event.check_state))
                )
            ])
        elif isinstance(event, events.StartingEvent):
            state_controller.states[event.comp_id].set_text([
                "state: STARTING..."
            ])
        elif isinstance(event, events.StoppingEvent):
            state_controller.states[event.comp_id].set_text([
                "state: STOPPING..."
            ])
        elif isinstance(event, events.CrashEvent):
            logger.warning("Component %s crashed!" % event.comp_id)
            state_controller.cc.check_component(state_controller.cc.get_component_by_id(event.comp_id))
            state_controller.states[event.comp_id].set_text([
                "state: ",
                ('darkred', "CRASHED")
            ])
        elif isinstance(event, events.SlaveReconnectEvent):
            logger.warn("Reconnected to slave on '%s'" % event.host_name)
            state_controller.fetch_host_items()
        elif isinstance(event, events.SlaveDisconnectEvent):
            logger.warn("Connection to slave on '%s' lost" % event.host_name)
            state_controller.fetch_host_items()
        elif isinstance(event, events.DisconnectEvent):
            logger.warning("Lost connection to host '%s'" % event.host_name)
            state_controller.fetch_host_items()
        elif isinstance(event, events.ReconnectEvent):
            logger.info("Reconnected to host '%s'" % event.host_name)
            state_controller.fetch_host_items()
        elif isinstance(event, events.StartReportEvent):
            state_controller.start_report_popup(event)
        elif isinstance(event, events.ServerDisconnectEvent):
            logger.critical("Server disconnected!")
            state_controller.handle_shutdown(None, False)
            # TODO: Show custom popup with option to quit or cancel
        elif isinstance(event, events.ConfigReloadEvent):
            state_controller.load_groups_from_config()
            state_controller.selected_group = state_controller.groups.keys()[0]
            state_controller.fetch_host_items()
            state_controller.fetch_components()
        else:
            logger.debug("Got unrecognized event of type: %s" % type(event))

    main_loop.set_alarm_in(.2, refresh, state_controller)


main_loop = None
