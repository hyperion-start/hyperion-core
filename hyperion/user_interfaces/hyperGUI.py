import hyperion.manager as manager
from PyQt4 import QtCore, QtGui
import sys
import threading
import subprocess
import logging
from functools import partial
from time import sleep
import hyperion.lib.util.config as config
import hyperion.lib.util.events as events

is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as queue
else:
    import queue as queue

SCRIPT_SHOW_TERM_PATH = ("%s/bin/show_term.sh" % manager.BASE_DIR)

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8


    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)


class UiMainWindow(object):

    def __init__(self, control_center):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.terms = {}
        self.threads = []
        self.animations = {}

        self.control_center = control_center  # type: manager.ControlCenter
        self.title = control_center.config['name']

        self.centralwidget = None
        self.verticalLayout = None
        self.tabWidget = None
        self.force_mode = False
        self.host_stats = None
        self.is_shutting_down = False
        self.event_manager = None

    def close(self):
        """Asks the user if a full shutdown is desired, then kills the manager instance and exits the GUI.

        :return: None
        """
        msg = QtGui.QMessageBox()
        msg.setIcon(QtGui.QMessageBox.Information)
        msg.setText("Do you want to shutdown the backend too?")
        msg.setWindowTitle("Closing PyQt GUI")
        msg.setStandardButtons(QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
        ret = msg.exec_()

        self.control_center.cleanup(ret == QtGui.QMessageBox.Yes)

    def ui_init(self, main_window):
        """Constructs the UI with all its components using information retrieved from ``control_center``.

        :param main_window: Window the UI is constructed in
        :type main_window: QtGui.QMainWindow
        :return: None
        """
        main_window.setObjectName(self.title)
        main_window.setWindowTitle("Hyperion: %s" % self.title)
        self.centralwidget = QtGui.QWidget(main_window)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.verticalLayout = QtGui.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))

        self.create_tabs()
        self.create_host_bar()
        self.create_all_components_section()

        self.verticalLayout.addWidget(self.tabWidget)
        main_window.setCentralWidget(self.centralwidget)
        self.tabWidget.setCurrentIndex(0)

        self.verticalLayout.addLayout(self.allComponentsWidget)

        split = QtGui.QFrame()
        split.setFrameShape(QtGui.QFrame.HLine)
        split.setFrameShadow(QtGui.QFrame.Sunken)
        self.verticalLayout.addWidget(split)

        self.verticalLayout.addLayout(self.hostWidget)

        event_manger = self.event_manager = EventManager(self.control_center)
        thread = QtCore.QThread()
        event_manger.forward_event_signal.connect(self.handle_event_forward_signal)

        event_manger.moveToThread(thread)
        event_manger.done.connect(thread.quit)
        thread.started.connect(event_manger.start)

        thread.start()
        self.threads.append(thread)
        event_manger.done.connect(lambda: self.threads.remove(thread))

    def create_all_components_section(self):
        """Creates a horizontal layout containing the `ALL COMPONENTS` section.

        :return: None
        """

        self.allComponentsWidget = container = QtGui.QHBoxLayout()
        container.setContentsMargins(0, 0, 1, 0)

        comp_label = QtGui.QLabel('ALL COMPONENTS: ', self.centralwidget)
        comp_label.setObjectName("comp_label_all")

        spacerItem = QtGui.QSpacerItem(20, 5, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Minimum)

        start_button = BlinkButton('Start', self.centralwidget)
        start_button.setObjectName("start_button_all")
        start_button.clicked.connect(lambda: self.control_center.start_all())
        start_button.setFocusPolicy(QtCore.Qt.NoFocus)

        stop_button = BlinkButton('Stop', self.centralwidget)
        stop_button.setObjectName("stop_button_all")
        stop_button.clicked.connect(lambda: self.handle_stop_all())
        stop_button.setFocusPolicy(QtCore.Qt.NoFocus)

        check_button = BlinkButton('Check', self.centralwidget)
        check_button.setObjectName("check_button_all")
        check_button.clicked.connect(lambda: self.handle_check_all())
        check_button.setFocusPolicy(QtCore.Qt.NoFocus)

        reload_button = BlinkButton('Reload Config', self.centralwidget)
        reload_button.setObjectName("reload_config_button")
        reload_button.clicked.connect(lambda: self.handle_reload_config())
        reload_button.setFocusPolicy(QtCore.Qt.NoFocus)

        spacerItem2 = QtGui.QSpacerItem(20, 5, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)

        container.addWidget(comp_label)
        container.addItem(spacerItem)
        container.addWidget(start_button)
        container.addWidget(stop_button)
        container.addWidget(check_button)
        container.addWidget(reload_button)

        container.addItem(spacerItem2)

    def create_host_bar(self):
        """Creates a horizontal layout containing the hosts section.

        :return: None
        """

        self.hostWidget = container = QtGui.QHBoxLayout()
        container.setContentsMargins(0,0,1,0)

        container.addWidget(QtGui.QLabel('SSH to: '))

        for host in self.control_center.host_list:
                host_button = BlinkButton('%s' % host, self.centralwidget)
                host_button.setObjectName("host_button_%s" % host)
                host_button.clicked.connect(partial(self.handle_host_button, host))
                host_button.setFocusPolicy(QtCore.Qt.NoFocus)

                if self.control_center.host_list.get(host):
                    host_button.setStyleSheet("background-color: green")
                else:
                    host_button.setStyleSheet("background-color: darkred")

                container.addWidget(host_button)
        container.addStretch(0)

    def create_tabs(self):
        """Creates a tab entry for every group.

        :return: None
        """
        if self.tabWidget:
            index = self.tabWidget.count()
            for i in range(index):
                self.tabWidget.widget(i).deleteLater()

        self.tabWidget = QtGui.QTabWidget(self.centralwidget)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))

        for group in self.control_center.config['groups']:
            groupTab = QtGui.QWidget()
            groupTab.setObjectName(group['name'])
            horizontalLayout = QtGui.QHBoxLayout(groupTab)
            horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
            scrollArea = QtGui.QScrollArea(groupTab)
            scrollArea.setWidgetResizable(True)
            scrollArea.setObjectName(_fromUtf8("scrollArea"))
            scrollAreaWidgetContents = QtGui.QWidget()
            scrollAreaWidgetContents.setObjectName(_fromUtf8("scrollAreaWidgetContents"))
            verticalLayout_compList = QtGui.QVBoxLayout(scrollAreaWidgetContents)
            verticalLayout_compList.setObjectName(_fromUtf8("verticalLayout_compList"))
            verticalLayout_compList.setContentsMargins(0, 0, 0, 0)
            for component in group['components']:
                verticalLayout_compList.addLayout(self.create_component(component, scrollAreaWidgetContents))
            verticalLayout_compList.addItem(QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding))

            scrollArea.setWidget(scrollAreaWidgetContents)
            horizontalLayout.addWidget(scrollArea)
            self.tabWidget.addTab(groupTab, group['name'])

    def create_component(self, comp, scrollAreaWidgetContents):
        """Creates a component entry for a tab.

        :param comp: Component to create UI objects for
        :type comp: dict
        :param scrollAreaWidgetContents: Parent scroll area content
        :type scrollAreaWidgetContents: QtQui.QWidget
        :return: Horizontal layout containing component UI objects
        :rtype: QtGui.QHBoxLayout
        """

        horizontalLayout_components = QtGui.QHBoxLayout()
        horizontalLayout_components.setObjectName(_fromUtf8("horizontalLayout_%s" % comp['id']))

        comp_label = QtGui.QLabel(scrollAreaWidgetContents)
        comp_label.setObjectName("comp_label_%s" % comp['id'])

        separator = QtGui.QSpacerItem(20, 5, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)

        status_pre_label = QtGui.QLabel(scrollAreaWidgetContents)
        status_pre_label.setText("Status: ")

        status_label = QtGui.QLabel(scrollAreaWidgetContents)
        status_label.setObjectName("comp_status_%s" % comp['id'])

        spacerItem = QtGui.QSpacerItem(20, 5, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)

        start_button = BlinkButton('test', scrollAreaWidgetContents)
        start_button.setObjectName("start_button_%s" % comp['id'])
        start_button.setText("start")
        start_button.clicked.connect(lambda: self.handle_start_button(comp))

        stop_button = BlinkButton(scrollAreaWidgetContents)
        stop_button.setObjectName("stop_button_%s" % comp['id'])
        stop_button.setText("stop")
        stop_button.clicked.connect(lambda: self.handle_stop_button(comp))

        check_button = BlinkButton(scrollAreaWidgetContents)
        check_button.setObjectName("check_button_%s" % comp['id'])
        check_button.setText("check")
        check_button.clicked.connect(lambda: self.handle_check_button(comp))

        term_toggle = QtGui.QCheckBox(scrollAreaWidgetContents)
        term_toggle.setObjectName("term_toggle_%s" % comp['id'])
        term_toggle.setText("Show Term")
        term_toggle.stateChanged.connect(lambda: self.handle_term_toggle_state_changed(comp, term_toggle.isChecked()))

        log_toggle = QtGui.QCheckBox(scrollAreaWidgetContents)
        log_toggle.setObjectName("log_toggle_%s" % comp['id'])
        log_toggle.setText("logging")

        log_button = QtGui.QPushButton(scrollAreaWidgetContents)
        log_button.setObjectName("log_button_%s" % comp['id'])
        log_button.setText("view log")
        log_button.clicked.connect(lambda: self.handle_log_button(comp))

        comp_label.raise_()
        comp_label.setText(comp['id'])

        status_label.raise_()
        status_label.setAutoFillBackground(True)

        status_label.setText("UNKNOWN")

        horizontalLayout_components.addWidget(comp_label)
        #horizontalLayout_components.addItem(separator)
        horizontalLayout_components.addItem(spacerItem)
        horizontalLayout_components.addWidget(status_pre_label)
        horizontalLayout_components.addWidget(status_label)
        horizontalLayout_components.addWidget(start_button)
        horizontalLayout_components.addWidget(stop_button)
        horizontalLayout_components.addWidget(check_button)
        horizontalLayout_components.addWidget(term_toggle)
        horizontalLayout_components.addWidget(log_toggle)
        horizontalLayout_components.addWidget(log_button)

        start_button.setFocusPolicy(QtCore.Qt.NoFocus)
        stop_button.setFocusPolicy(QtCore.Qt.NoFocus)
        term_toggle.setFocusPolicy(QtCore.Qt.NoFocus)
        log_toggle.setFocusPolicy(QtCore.Qt.NoFocus)
        log_button.setFocusPolicy(QtCore.Qt.NoFocus)
        check_button.setFocusPolicy(QtCore.Qt.NoFocus)

        return horizontalLayout_components

    def handle_host_button(self, host):
        """Handle a click on a specific host button.

        If the host is local host, a simple xterm is opened. If it is a remote host, an xterm with an ssh connection to
        the host is opened.

        :param host: Host whose button was clicked
        :type host: str
        :return: None
        """
        if self.control_center.is_localhost(host):
            self.logger.debug("Clicked host is localhost. Opening xterm")
            subprocess.Popen(['xterm'], stdout=subprocess.PIPE)
        elif self.control_center.host_list.get(host):
            self.logger.debug("Clicked host remote host. Opening xterm with ssh")
            cmd = 'ssh -F %s %s' % (config.CUSTOM_SSH_CONFIG_PATH, host)
            subprocess.Popen(['xterm', '-e', '%s' % cmd], stdout=subprocess.PIPE)
        elif self.control_center.reconnect_with_host(host):
            self.logger.debug("Clicked remote host is up again! Opening xterm with ssh")
            host_button = self.centralwidget.findChild(QtGui.QPushButton, "host_button_%s" % host)
            host_button.setStyleSheet("background-color: green")
            cmd = 'ssh -F %s %s' % (config.CUSTOM_SSH_CONFIG_PATH, host)
            subprocess.Popen(['xterm', '-e', '%s' % cmd], stdout=subprocess.PIPE)
        else:
            self.logger.error("Clicked remote host is down!")

            msg = QtGui.QMessageBox()
            msg.setIcon(QtGui.QMessageBox.Warning)
            msg.setText("Could not connect to host '%s'" % host)
            msg.setWindowTitle("Error")
            msg.setStandardButtons(QtGui.QMessageBox.Close)

            msg.exec_()

    def handle_reload_config(self):
        self.logger.info("Clicked reload config")
        threading.Thread(
            target=self.control_center.reload_config, name='reload_config',
        ).start()

    def handle_log_button(self, comp):
        """Handles a click on a components log button.

        Opens up an xterm displaying a log file with tail -F.

        :param comp: Component whose log button was clicked
        :type comp: dict
        :return: None
        """

        self.logger.debug("%s show log button pressed" % comp['id'])

        cmd = "tail -n +1 -F %s/%s/latest.log" % (config.TMP_LOG_PATH, comp['id'])

        if self.control_center.run_on_localhost(comp):
            subprocess.Popen(['xterm', '-fg', 'white', '-bg', 'darkblue', '-title', 'log of %s' % comp['id'],
                              '-e', '%s' % cmd], stdout=subprocess.PIPE)

        else:
            subprocess.Popen(['xterm', '-fg', 'white', '-bg', 'darkblue', '-title',
                              'log of %s on %s' % (comp['id'], comp['host']),
                              '-e', "ssh %s -t 'bash -c \"%s\"'" % (comp['host'], cmd)],
                             stdout=subprocess.PIPE)

    def handle_start_all(self):
        """Handles a click on the start all button.

        :return: None
        """
        self.logger.debug("Start all button pressed")

        threading.Thread(
            target=self.control_center.start_all, args=[],
            name='start_all',
        ).start()

    def handle_start_button(self, comp):
        """Handles a click on a components start button.

        :param comp: Component whose start button was clicked
        :type comp: dict
        :return: None
        """
        self.logger.info("Clicked start %s" % comp['id'])
        threading.Thread(
            target=self.control_center.start_component, args=[comp, self.force_mode],
            name='start_comp_%s' % comp['id'],
        ).start()

    def handle_stop_button(self, comp):
        """Handles a click on a components stop button.

        :param comp: Component whose stop button was clicked
        :type comp: dict
        :return: None
        """
        self.logger.info("Clicked stop %s" % comp['id'])
        threading.Thread(
            target=self.stop_component, args=[comp],
            name='stop_comp_%s' % comp['id'],
        ).start()

        term_toggle = self.centralwidget.findChild(QtGui.QCheckBox, "term_toggle_%s" % comp['id'])
        if term_toggle.isChecked():
            term_toggle.setChecked(False)

    def stop_component(self, comp):
        """Stop component and run a component check right afterwards to update the ui status.

        :param comp: Component that will be stopped
        :type comp: dict
        :return: None
        """
        self.control_center.stop_component(comp)
        sleep(1)
        threading.Thread(
            target=self.control_center.check_component, args=[comp],
            name='check_comp_%s' % comp['id'],
        ).start()

    def handle_stop_all(self):
        """Handles a click on the `stop all` button.

        Executes a ``handle_stop_button`` call for each component.

        :return: None
        """
        self.logger.info("Clicked stop all")
        threading.Thread(
            target=self.control_center.stop_all, args=[],
            name='stop_comp_all',
        ).start()

    def handle_check_button(self, comp):
        """Handles a click on a components check button.

        :param comp: Component whose check button was clicked
        :type comp: dict
        :return: None
        """
        self.logger.info("Clicked check %s" % comp['id'])
        threading.Thread(
            target=self.control_center.check_component, args=[comp],
            name='check_comp_%s' % comp['id'],
        ).start()

    def handle_check_all(self):
        """Handles a click on the `check all` button.

        :return: None
        """
        for group in self.control_center.config['groups']:
            for comp in group['components']:
                self.handle_check_button(comp)

    def handle_term_toggle_state_changed(self, comp, is_checked):
        """Handles toggle or de-toggle of a components show term checkbox.

        Opens or closes an xterm with attached to a components (remote or local) tmux window in a cloned tmux session.

        :param comp: Component whose show term checkbox was clicked
        :type comp: dict
        :param is_checked: Current state of the checkbox
        :type is_checked: bool
        :return: None
        """

        self.logger.debug("%s show term set to: %d" % (comp['id'], is_checked))

        if is_checked:

            if self.control_center.run_on_localhost(comp):
                self.logger.debug("Starting local clone session")
                self.control_center.start_local_clone_session(comp)

                # Safety wait to ensure clone session is running
                sleep(.5)
                term = subprocess.Popen([("%s" % SCRIPT_SHOW_TERM_PATH),
                                         ("%s-clone-session" % comp['id'])], stdout=subprocess.PIPE)

                self.terms[comp['id']] = term
            else:
                self.logger.debug("Starting remote clone session")
                self.control_center.start_remote_clone_session(comp)

                # Safety wait to ensure clone session is running
                sleep(.5)
                self.logger.debug("Open xterm with ssh")
                term = subprocess.Popen([("%s" % SCRIPT_SHOW_TERM_PATH),
                                         ("%s-clone-session" % comp['id']),
                                         ("%s" % comp['host'])],
                                        stdout=subprocess.PIPE)
                self.terms[comp['id']] = term

        else:
            self.logger.debug("Closing xterm")
            term = self.terms[comp['id']]
            if term.poll() is None:
                self.logger.debug("Term %s still running. Trying to kill it" % comp['id'])

                if self.control_center.run_on_localhost(comp):
                    self.logger.debug("Session '%s' is running locally" % comp['id'])
                    self.control_center.kill_session_by_name("%s-clone-session" % comp['id'])
                else:
                    self.logger.debug("Session '%s' is running on remote host %s" % (comp['id'], comp['host']))
                    self.control_center.kill_remote_session_by_name("%s-clone-session" % comp['id'], comp['host'])
            else:
                self.logger.debug("Term already closed! Command must have crashed. Open log!")

    @QtCore.pyqtSlot(events.BaseEvent)
    def handle_event_forward_signal(self, event):
        logger = logging.getLogger(__name__)

        logger.debug("Got event: %s" % event)

        if isinstance(event, events.CheckEvent):
            logger.debug("Check event - comp %s; state %s" % (event.comp_id, event.check_state))
            status_label = self.centralwidget.findChild(QtGui.QLabel, "comp_status_%s" % event.comp_id)
            status_label.setStyleSheet(
                "QLabel { background-color: %s; }" % config.STATE_CHECK_BUTTON_STYLE.get(event.check_state)
            )
            status_label.setText(config.SHORT_STATE_DESCRIPTION.get(event.check_state))
        elif isinstance(event, events.StartingEvent):
            status_label = self.centralwidget.findChild(QtGui.QLabel, "comp_status_%s" % event.comp_id)
            status_label.setStyleSheet("")
            status_label.setText("STARTING...")
        elif isinstance(event, events.StoppingEvent):
            status_label = self.centralwidget.findChild(QtGui.QLabel, "comp_status_%s" % event.comp_id)
            status_label.setStyleSheet("")
            status_label.setText("STOPPING...")
        elif isinstance(event, events.CrashEvent):
            logger.warning("Component %s crashed!" % event.comp_id)
            status_label = self.centralwidget.findChild(QtGui.QLabel, "comp_status_%s" % event.comp_id)
            status_label.setStyleSheet("")
            status_label.setText("CRASHED")
        elif isinstance(event, events.SlaveReconnectEvent):
            logger.warn("Reconnected to slave on '%s'" % event.host_name)
            self.create_host_bar()
        elif isinstance(event, events.SlaveDisconnectEvent):
            logger.warn("Connection to slave on '%s' lost" % event.host_name)
            self.create_host_bar()
        elif isinstance(event, events.DisconnectEvent):
            logger.warning("Lost connection to host '%s'" % event.host_name)
            self.create_host_bar()
        elif isinstance(event, events.ReconnectEvent):
            logger.info("Reconnected to host '%s'" % event.host_name)
            self.create_host_bar()
        elif isinstance(event, events.StartReportEvent):
            logger.debug("START REPORT RECEIVED")
            self.create_host_bar()
        elif isinstance(event, events.ServerDisconnectEvent):
            logger.critical("Server disconnected!")
            # state_controller.handle_shutdown(None, False)
            # TODO: Show custom popup with option to quit or cancel
        elif isinstance(event, events.ConfigReloadEvent):
            logger.debug("CONFIG RELOAD TRIGGERED")
            self.verticalLayout.removeWidget(self.tabWidget)
            self.create_tabs()
            self.create_host_bar()
            self.verticalLayout.insertWidget(0, self.tabWidget)
        else:
            logger.debug("Got unrecognized event of type: %s" % type(event))
    sleep(.7)

    @QtCore.pyqtSlot(str, int, bool)
    def handle_crash_signal(self, check_status, comp_name, unused):
        """Handler for a crash signal event that informs the user of a component crash.

        :param check_status: Status generated by the check of the crashed component
        :type check_status: int
        :param comp_name: Name of the crashed component
        :type comp_name: str
        :return: None
        """
        check_status = config.CheckState(check_status)
        if check_status is config.CheckState.STOPPED:
            msg = QtGui.QMessageBox()
            msg.setIcon(QtGui.QMessageBox.Critical)
            msg.setText("Component '%s' crashed!" % comp_name)
            msg.setWindowTitle("Error")
            msg.setStandardButtons(QtGui.QMessageBox.Close)

            msg.exec_()

            self.logger.debug("Component %s stopped!" % comp_name)

    @QtCore.pyqtSlot(str)
    def handle_disconnect_signal(self, hostname):
        """Handles a disconnect signal event that informs the user of a connection loss to a host.

        :param hostname: Name of the host the connection to was lost
        :type hostname: str
        :return: None
        """

        host_button = self.centralwidget.findChild(QtGui.QPushButton, "host_button_%s" % hostname)
        host_button.setStyleSheet("background-color: darkred")

        msg = QtGui.QMessageBox()
        msg.setIcon(QtGui.QMessageBox.Critical)
        msg.setText("Lost connection to '%s'!" % hostname)
        msg.setWindowTitle("Error")
        msg.setStandardButtons(QtGui.QMessageBox.Retry | QtGui.QMessageBox.Close)

        retval = msg.exec_()

        if retval == QtGui.QMessageBox.Retry:
            self.logger.debug("Chose retry connecting to %s" % hostname)
            if not self.control_center.reconnect_with_host(hostname):
                msg = QtGui.QMessageBox()
                msg.setIcon(QtGui.QMessageBox.Critical)
                msg.setText("Could not establish connection to '%s'. Will retry periodically in background." % hostname)
                msg.setWindowTitle("Error")
                msg.setStandardButtons(QtGui.QMessageBox.Close)

                msg.exec_()
            else:
                host_button.setStyleSheet("background-color: green")
                self.logger.debug("Reconnect successful")

    @QtCore.pyqtSlot(int, str, bool)
    def check_button_callback(self, check_state, comp_name, popup):
        """Handles the signal for a finished component check execution displaying user information on a fail.

        :param check_state: Status returned by the component check
        :type check_state: int
        :param comp_name: Name of the checked component
        :type comp_name: str
        :return: None
        """

        check_state = config.CheckState(check_state)
        check_button = self.centralwidget.findChild(QtGui.QPushButton, "check_button_%s" % comp_name)

        check_button.setStyleSheet("background-color: %s" % config.STATE_CHECK_BUTTON_STYLE.get(check_state))

        check_button.setEnabled(True)

        if self.animations.has_key("start_%s" % comp_name):
            self.animations.pop("start_%s" % comp_name).stop()
            start_button = self.centralwidget.findChild(QtGui.QPushButton, "start_button_%s" % comp_name)
            start_button.setColor(QtGui.QColor(255, 255, 255))
            start_button.setEnabled(True)

        if self.animations.has_key("check_%s" % comp_name):
            self.animations.pop("check_%s" % comp_name).stop()
            check_button.setColor(QtGui.QColor(255, 255, 255))

        if self.animations.has_key("stop_%s" % comp_name):
            self.animations.pop("stop_%s" % comp_name).stop()
            stop_button = self.centralwidget.findChild(QtGui.QPushButton, "stop_button_%s" % comp_name)
            stop_button.setColor(QtGui.QColor(255, 255, 255))
            stop_button.setEnabled(True)

        if popup:
            if check_state is config.CheckState.NOT_INSTALLED or check_state is config.CheckState.UNREACHABLE:
                msg = QtGui.QMessageBox()
                msg.setIcon(QtGui.QMessageBox.Critical)
                msg.setText("'%s' failed with status: %s" % (comp_name, config.STATE_DESCRIPTION.get(check_state)))
                msg.setWindowTitle("Error")
                msg.setStandardButtons(QtGui.QMessageBox.Close)
                msg.exec_()

    @QtCore.pyqtSlot(int, dict, str)
    def start_button_callback(self, check_state, comp, failed_name):
        """Handles the signal for a finished component start displaying user information on a fail.

        :param check_state: Status of the component check run after the start
        :type check_state: int
        :param comp: Component that was started
        :type comp: dict
        :param failed_name: Name of a dependency that failed during the start process (dummy if none failed)
        :type failed_name: str
        :return: None
        """

        try:
            start_state = config.StartState(check_state)
        except ValueError:
            start_state = None

        try:
            check_state = config.CheckState(check_state)
        except ValueError:
            check_state = None

        msg = QtGui.QMessageBox()
        if check_state is config.CheckState.DEP_FAILED:
            msg.setIcon(QtGui.QMessageBox.Warning)
            msg.setText("Start process of '%s' was interrupted" % comp['id'])
            msg.setInformativeText("Dependency '%s' failed!" % failed_name)
            msg.setWindowTitle("Warning")
            msg.setStandardButtons(QtGui.QMessageBox.Retry | QtGui.QMessageBox.Cancel)
            self.logger.debug("Warning, start process of '%s' was interrupted. Dependency '%s' failed!" %
                              (comp['id'], failed_name))
            retval = msg.exec_()

            if retval == QtGui.QMessageBox.Retry:
                self.handle_start_button(comp)

        elif check_state is config.CheckState.STOPPED:
            msg.setIcon(QtGui.QMessageBox.Warning)
            msg.setText("Failed starting '%s'" % comp['id'])
            msg.setWindowTitle("Warning")
            msg.setStandardButtons(QtGui.QMessageBox.Retry | QtGui.QMessageBox.Cancel)
            retval = msg.exec_()

            if retval == QtGui.QMessageBox.Retry:
                self.handle_start_button(comp)
        elif start_state is config.StartState.ALREADY_RUNNING:
            self.logger.debug("Component '%s' already running!" % comp['id'])
            msg.setIcon(QtGui.QMessageBox.Warning)
            msg.setText("Component '%s' already running!" % comp['id'])
            msg.setWindowTitle("Warning")
            msg.setStandardButtons(QtGui.QMessageBox.Ok)
            msg.exec_()
        else:
            self.logger.debug("Starting '%s' succeeded without interference" % comp['id'])
            return

    @QtCore.pyqtSlot(int, dict, str)
    def start_all_callback(self, start_state, failed_comps, unused):
        """Handles the done signal of a start all worker thread.

        :param check_state: Final state of the start all process
        :type check_state: int
        :param comp: Unused dummy (provided because the same signal as for a single component start is used)
        :type comp: dict
        :param failed_name: Unused dummy (provided because the same signal as for a single component start is used)
        :type failed_name: str
        :return: None
        """

        start_state = config.StartState(start_state)

        start_button = self.centralwidget.findChild(QtGui.QPushButton, "start_button_all")

        if self.animations.has_key("start_all"):
            self.animations.pop("start_all").stop()
        start_button.setEnabled(True)
        start_button.setStyleSheet("")

        if start_state is config.StartState.STARTED:
            self.logger.debug("Start all succeeded")
        else:
            start_button.setStyleSheet("background-color: red")
            self.logger.debug("Start all failed")

            details = ''
            for comp_name in failed_comps:
                details += '%s: %s\n' % (comp_name, config.STATE_DESCRIPTION.get(failed_comps.get(comp_name)))

            msg = QtGui.QMessageBox()
            msg.setIcon(QtGui.QMessageBox.Warning)
            msg.setWindowTitle("Start all failed!")
            msg.setText(details)
            msg.setStandardButtons(QtGui.QMessageBox.Ok)
            msg.exec_()


class EventManager(QtCore.QObject):
    """Class that handles events sent by the main applications monitoring thread."""
    forward_event_signal = QtCore.pyqtSignal(events.BaseEvent)
    done = QtCore.pyqtSignal()

    def __init__(self, control_center, parent=None, is_ending=False):
        super(self.__class__, self).__init__(parent)
        self.is_ending = is_ending
        self.control_center = control_center

    def shutdown(self):
        """Shutown the event manager thread safely by setting the main loop condition to false.

        :return: None
        """
        self.is_ending = True

    @QtCore.pyqtSlot()
    def start(self):
        """Starts the EventManager main loop and subscribes to the monitoring thread event queue.

        Emits signals to the UI thread to notify it about monitoring events.
        Signals its termination by emitting a ``done`` signal.

        :return: None
        """
        event_queue = queue.Queue()
        self.control_center.add_subscriber(event_queue)

        while not self.is_ending:
            while not event_queue.empty():
                event = event_queue.get_nowait()
                self.forward_event_signal.emit(event)
            sleep(.7)
        self.done.emit()


class BlinkButton(QtGui.QPushButton):
    """QPushbutton extension adding a color attribute to enable an animation for the foreground color."""
    def __init__(self, *args, **kwargs):
        QtGui.QPushButton.__init__(self, *args, **kwargs)
        self.default_color = self.getColor()

    def getColor(self):
        return self.palette().color(QtGui.QPalette.Button)

    def setColor(self, value):
        if value == self.getColor():
            return
        palette = self.palette()
        palette.setColor(self.foregroundRole(), value)
        self.setAutoFillBackground(True)
        self.setPalette(palette)

    def reset_color(self):
        self.setColor(self.default_color)

    color = QtCore.pyqtProperty(QtGui.QColor, getColor, setColor)
