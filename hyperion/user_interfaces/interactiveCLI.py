import urwid


class StateController(object):
    """Intermediate interface class that constructs a urwid UI connected to the core application."""

    def __init__(self, cc):
        """Initialize StateController constructing the urwid UI.

        :param cc: Reference to core application
        :type cc: hyperion.ControlCenter
        """

        self.cc = cc
        self.selected_group = 0
        self.groups = []

        header_text = urwid.Text(u'%s' % cc.config['name'])
        header = urwid.AttrMap(header_text, 'titlebar')
        menu = urwid.Text([
            u'Press (', ('refresh button', u'N'), u') for next or (', ('refresh button', u'P'), u') for previous group | ',
            u'Press (', ('quit button', u'Q'), u') to quit.'
        ])

        for g in self.cc.config['groups']:
            self.groups.append(g)
        self.groups.append({'name': 'All'})

        groups = self.get_group_items()

        group_bar = urwid.Columns(groups)
        group_filler = self.group_filler = urwid.Filler(group_bar, valign='top', top=1)

        active_comps = self.active_comps = urwid.SimpleFocusListWalker([urwid.Text("Nothing to display")])

        self.group_changed()

        comp_box = urwid.ListBox(active_comps)
        v_padding = urwid.Padding(comp_box, left=1, right=1)
        state_box = urwid.LineBox(v_padding)
        v_padding_states = urwid.Padding(state_box, left=2, right=2)

        main_body = self.main_body = urwid.Pile([group_filler, v_padding_states])
        self.layout = urwid.Frame(header=header, body=main_body, footer=menu)

    def refresh_group_status(self):
        """Refresh the displayed groups (highlighting).

        :returns: None
        """

        self.group_filler.body = urwid.Columns(self.get_group_items())

    def get_group_items(self):
        """Get groups defined in the configuration file and add an 'all' group.

        :return: None
        """

        groups = []
        for g in self.cc.config['groups']:
            grp = urwid.LineBox(urwid.Text(g['name']))
            if g['name'] == self.groups[self.selected_group]['name']:
                grp = urwid.AttrMap(grp, 'group_selected')
            else:
                grp = urwid.AttrMap(grp, 'group')
            groups.append(grp)

        all_group = urwid.LineBox(urwid.Text(u'All'))
        if self.groups[self.selected_group]['name'] == 'All':
            all_group = urwid.AttrMap(all_group, 'group_selected')
        else:
            all_group = urwid.AttrMap(all_group, 'group')
        groups.append(all_group)

        return groups

    def change_group(self, val):
        """Change the currently selected group.

        :param val: Change of the index in the group list
        :type val: int
        :return: None
        """

        if len(self.groups) > self.selected_group + val > -1:
            self.selected_group = self.selected_group + val
            self.group_changed()

    def comp_action_cb(self, button, action):
        """Handle a component action menu button click.

        Does nothing yet except resetting the view, since this state is just a prototype.

        :param button: Clicked button
        :type button: uriwd.Button
        :param action: Component menu action name
        :type action: str
        :return: None
        """

        main_loop.widget = self.layout

    def selected_comp(self, comp_button, comp):
        """Shows component action menu as popup.

        :param comp_button: Button that caused the callback
        :type comp_button: urwid.Button
        :param comp: Component belonging to the selected button
        :type comp: dict
        :return: None
        """

        body = [urwid.Text("%s component menu" % comp['name']), urwid.Divider()]

        choices = u'Start Stop Check Log'.split()
        for c in choices:
            button = urwid.Button(c)
            urwid.connect_signal(button, 'click', self.comp_action_cb, c)
            body.append(urwid.AttrMap(button, None, focus_map='reversed'))

        box = urwid.ListBox(urwid.SimpleFocusListWalker(body))
        lb = urwid.AttrMap(urwid.LineBox(box), 'popup')

        overlay = urwid.Overlay(lb, self.main_body, align='center', width=('relative', 60),
                      valign='middle', height=('relative', 60))
        main_loop.widget = urwid.Frame(overlay)

    def group_changed(self):
        """Reloads components to display and triggers a group status display refresh.

        :return: None
        """

        group = self.groups[self.selected_group]

        comps = []
        if group['name'] != 'All':
            for c in group['components']:
                button = urwid.Button("%s@%s - Status: %s " % (c['name'], c['host'], "DUMMY"))
                urwid.connect_signal(button, 'click', self.selected_comp, c)
                comps.append(urwid.AttrMap(button, None, focus_map='reversed'))
        else:
            for grp in self.groups:
                if grp['name'] != 'All':
                    for c in grp['components']:
                        button = urwid.Button("%s@%s - Status: %s " % (c['name'], c['host'], "DUMMY"))
                        urwid.connect_signal(button, 'click', self.selected_comp, c)
                        comps.append(urwid.AttrMap(button, None, focus_map='reversed'))

        self.active_comps[0] = urwid.Pile(comps)
        self.refresh_group_status()

    def handle_input(self, key):
        """Handle user input that was not handled by active urwid components.

        :param key: User input to process
        :type key: str
        :return: None
        """
        if key == 'R' or key == 'r':
            refresh(main_loop, '')

        if key == 'Q' or key == 'q':
            raise urwid.ExitMainLoop()

        if key == 'p' or key == 'P':
            self.change_group(-1)
        if key == 'n' or key == 'N':
            self.change_group(1)

        if key == 'esc':
            main_loop.widget = self.layout


def main(cc):
    """Creates a state controller and starts urwid.

    :param cc: Reference to the core application
    :type cc: hyperion.ControlCenter
    :return: None
    """

    cli_menu = StateController(cc)

    palette = [
        ('titlebar', 'dark red', ''),
        ('popup', 'black', 'dark cyan'),
        ('refresh button', 'dark green,bold', ''),
        ('reversed', 'standout', ''),
        ('quit button', 'dark red', ''),
        ('button', 'black', 'light gray'),
        ('button_select', 'light gray', 'black'),
        ('group', 'black', "white"),
        ('group_selected', 'white', 'dark blue'),
        ('getting quote', 'dark blue', ''),
        ('headers', 'white,bold', ''),
        ('change ', 'dark green', ''),
        ('change negative', 'dark red', '')]

    global main_loop
    main_loop = urwid.MainLoop(cli_menu.layout, palette, unhandled_input=cli_menu.handle_input, pop_ups=True)
    # main_loop.set_alarm_in(0, refresh)
    main_loop.run()


def refresh(_loop, _data):
    """Refresh the display and set an automatic trigger for 10 seconds.

    :param _loop: Urwid main loop
    :param _data:
    :return: None
    """

    main_loop.draw_screen()
    main_loop.set_alarm_in(10, refresh)


main_loop = None
