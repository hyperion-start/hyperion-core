import urwid
import hyperion.lib.util.config as config
import logging
import sys

is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as queue
else:
    import queue as queue


class LogTextWalker(urwid.ListWalker):
    """ListWalker-compatible class for lazily reading file contents."""

    def __init__(self, name):
        self.file_name = name
        self.file = open(name)
        self.lines = []
        self.focus = 0
        self.end = False
        self.max_pos = 0

    def get_focus(self):
        return self._get_at_pos(self.focus)

    def set_focus(self, focus):
        self.focus = focus
        self._modified()

    def get_next(self, start_from):
        return self._get_at_pos(start_from + 1)

    def get_prev(self, start_from):
        return self._get_at_pos(start_from - 1)

    def read_next_line(self):
        """Read another line from the file."""

        next_line = self.file.readline()

        if not next_line or next_line[-1:] != '\n':
            # no newline on last line of file
            self.end = True
        else:
            # trim newline characters
            self.end = False
            next_line = next_line[:-1]

        self.lines.append(urwid.Text(next_line))
        return next_line

    def reread_last_line(self):
        """Read another line from the file and replace last line with it."""

        next_line = self.file.readline()

        if not next_line or next_line[-1:] != '\n':
            # no newline on last line of file
            self.end = True
        else:
            # trim newline characters
            self.end = False
            next_line = next_line[:-1]

        self.lines[-1] = urwid.Text(next_line)
        return next_line

    def _get_at_pos(self, pos):
        """Return a widget for the line number passed."""

        if pos < 0:
            # line 0 is the start of the file, no more above
            return None, None

        self.max_pos = pos

        if len(self.lines) > pos:
            # we have that line so return it
            return self.lines[pos], pos

        if self.end:
            with open(self.file_name) as f:
                for i, l in enumerate(f):
                    pass
                self.max_pos = i+1
                logging.debug("file lines %s; pos %s" % (i, pos))
                if i+1 < pos:
                    return None, None
                else:
                    self.reread_last_line()
                    return self.lines[-1], pos-1

        assert pos == len(self.lines), "out of order request?"

        self.read_next_line()

        return self.lines[-1], pos

    def combine_focus_with_prev(self):
        """Combine the focus edit widget with the one above."""

        above, ignore = self.get_prev(self.focus)
        if above is None:
            # already at the top
            return

        focus = self.lines[self.focus]
        above.set_edit_pos(len(above.edit_text))
        above.set_edit_text(above.edit_text + focus.edit_text)
        del self.lines[self.focus]
        self.focus -= 1

    def combine_focus_with_next(self):
        """Combine the focus edit widget with the one below."""

        below, ignore = self.get_next(self.focus)
        if below is None:
            # already at bottom
            return

        focus = self.lines[self.focus]
        focus.set_edit_text(focus.edit_text + below.edit_text)
        del self.lines[self.focus+1]


class SimpleButton(urwid.Button):
    def __init__(self, caption, callback=None, user_data=None):
        super(SimpleButton, self).__init__("")
        if callback:
            urwid.connect_signal(self, 'click', callback, user_data)
        label = urwid.SelectableIcon(caption, 0)
        label.set_align_mode('center')
        self._w = urwid.AttrMap(label, None, 'selected')


class StateController(object):
    """Intermediate interface class that constructs a urwid UI connected to the core application."""

    def __init__(self, cc, event_queue):
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
        self.log_viewer = LogTextWalker('%s/info.log' % config.TMP_LOG_PATH)
        self.tail_log = True
        self.last_content_focus = 0

        header_text = urwid.Text(u'%s' % cc.config['name'], align='center')
        header = urwid.Pile([urwid.Divider(), urwid.AttrMap(header_text, 'titlebar')])

        for g in self.cc.config['groups']:
            self.groups[g['name']] = g
        self.groups['All'] = ({'name': 'All'})

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

        blank = urwid.Divider()
        list_box_contents = [
            blank,
            urwid.Divider('='),
            group_col,
            urwid.Divider('='),

            urwid.Padding(urwid.LineBox(components_pile), left=2, right=2),

            urwid.Columns([
                urwid.Pile([
                    urwid.LineBox(urwid.Pile([
                        urwid.Columns([
                            SimpleButton('Start'),
                            SimpleButton('Stop'),
                            SimpleButton('Check')
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

                urwid.LineBox(urwid.Pile([
                    urwid.BoxAdapter(urwid.ListBox(LogTextWalker('/tmp/Hyperion/ssh-config')), 10),
                    urwid.Divider(),
                    urwid.AttrMap(SimpleButton("Close"), 'titlebar')
                ]), 'Log')
            ], 1),
        ]

        menu = self.menu = urwid.Pile([
            urwid.Divider(),
            urwid.Padding(urwid.Divider('#'), left=10, right=10),
            urwid.Divider(),
            urwid.LineBox(urwid.BoxAdapter(urwid.ListBox(self.log_viewer), 10), 'Hyperion Log'),
            urwid.Text([
                u'Press (', ('refresh button', u'L'), u') to jump into or out of Hyperion log | ',
                u'Press (', ('quit button', u'Q'), u') to quit.'
            ])
        ])

        self.fetch_group_items()
        self.fetch_components()
        self.fetch_host_items()

        self.content_walker = urwid.SimpleListWalker(list_box_contents)

        main_body = self.main_body = urwid.ListBox(self.content_walker)
        self.layout = urwid.Frame(header=header, body=main_body, footer=menu)

    def fetch_host_items(self):
        """Get all hosts to display in the UI.

        :return None
        """

        hosts = []
        for host in self.cc.host_list:
            host_object = SimpleButton(host)
            if self.cc.host_list[host]:
                host_object = urwid.AttrMap(host_object, 'host', focus_map='reversed')
            else:
                host_object = urwid.AttrMap(host_object, 'unavailable_host', focus_map='reversed')

            hosts.append((urwid.Columns([
                host_object,
                urwid.Text('4', align='center'),
                urwid.Text('100%', align='center'),
                urwid.Text('100%', align='center')
            ], 1), ('weight', 1)))

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
                comps.append((urwid.Columns([
                    urwid.AttrMap(SimpleButton('%s@%s' % (c['name'], c['host'])), 'important', focus_map='reversed'),
                    urwid.Text('status: ???'),
                    SimpleButton('Start'),
                    SimpleButton('Stop'),
                    SimpleButton('Check'),
                    urwid.CheckBox('Log'),
                ], 1), ('weight', 1)))

        else:
            for grp in self.groups:
                group = self.groups[grp]
                if group['name'] != 'All':
                    for c in group['components']:
                        comps.append((urwid.Columns([
                            urwid.AttrMap(SimpleButton('%s@%s' % (c['name'], c['host'])), 'important',
                                          focus_map='reversed'),
                            urwid.Text('status: ???'),
                            SimpleButton('Start'),
                            SimpleButton('Stop'),
                            SimpleButton('Check'),
                            urwid.CheckBox('Log'),
                        ], 1), ('weight', 1)))

        self.components_pile.contents[:] = comps

    def handle_input(self, key):
        """Handle user input that was not handled by active urwid components.

        :param key: User input to process
        :type key: str
        :return: None
        """

        if key == 'Q' or key == 'q':
            raise urwid.ExitMainLoop()

        if key == 'esc':
            main_loop.widget = self.layout

        if key == 'L' or key == 'l':
            if self.tail_log:
                ignore, pos = self.content_walker.get_focus()
                self.last_content_focus = pos
                self.content_walker.set_focus(len(self.content_walker.contents)-1)
                self.tail_log = False
            else:
                self.content_walker.set_focus(self.last_content_focus)
                self.tail_log = True


def main(cc):
    """Creates a state controller and starts urwid.

    :param cc: Reference to the core application
    :type cc: hyperion.ControlCenter
    :return: None
    """

    event_queue = queue.Queue()
    cli_menu = StateController(cc, event_queue)

    palette = [
        ('titlebar', 'dark red', ''),
        ('refresh button', 'dark green,bold', ''),
        ('reversed', 'standout', ''),
        ('quit button', 'dark red', ''),
        ('button', 'black', 'light gray'),
        ('button_select', 'light gray', 'black'),
        ('group', 'black', "white"),
        ('group_selected', 'white', 'dark cyan'),
        ('headers', 'white,bold', ''),
        ('host', 'dark green', ''),
        ('unavailable_host', 'dark red', ''),
        ('important', 'dark blue', 'black', ('standout', 'underline')),
        ('selected', 'white', 'dark blue'),
        ('deselected', 'white', 'light gray')]

    global main_loop
    main_loop = urwid.MainLoop(cli_menu.layout, palette, unhandled_input=cli_menu.handle_input, pop_ups=True)
    main_loop.set_alarm_in(0, refresh, cli_menu)
    main_loop.run()


def refresh(_loop, state_controller, _data=None):
    """Update Hyperion logger and set an automatic trigger for .5 seconds.

    :param _loop: Urwid main loop
    :param _data:
    :param state_controller: Reference to UI manager
    :type state_controller: StateController
    :return: None
    """

    state_controller.log_viewer._modified()
    if state_controller.tail_log:
        state_controller.log_viewer.set_focus(state_controller.log_viewer.max_pos)
    event_queue = state_controller.event_queue

    while not event_queue.empty():
        event = event_queue.get_nowait()

    main_loop.set_alarm_in(.5, refresh, state_controller)



main_loop = None
