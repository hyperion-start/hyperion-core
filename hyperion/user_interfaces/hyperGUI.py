import hyperion.manager as manager
from PyQt4 import QtCore, QtGui
import sys
import subprocess
import logging
from functools import partial
from time import sleep
import hyperion.lib.util.config as config
from hyperion.lib.monitoring.threads import LocalCrashEvent, RemoteCrashEvent, DisconnectEvent

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

    def close(self):
        """Asks the user if a full shutdown is desired, then kills the manager instance and exits the GUI.

        :return: None
        """

        msg = QtGui.QMessageBox()
        msg.setIcon(QtGui.QMessageBox.Information)
        msg.setText("Do you want to close all running processes?")
        msg.setWindowTitle("Closing Application")
        msg.setStandardButtons(QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
        ret = msg.exec_()

        self.event_manager.shutdown()
        self.control_center.cleanup(ret == QtGui.QMessageBox.Yes)
        exit(0)

    def ui_init(self, main_window, control_center):
        """Constructs the UI with all its components using information retrieved from ``control_center``.

        :param main_window: Window the UI is constructed in
        :type main_window: QtGui.QMainWindow
        :param control_center: Managing interface holding all configuration information
        :type control_center: manager.ControlCenter
        :return: None
        """

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.terms = {}
        self.threads = []
        self.animations = {}

        self.control_center = control_center  # type: manager.ControlCenter
        self.title = control_center.session_name

        self.logger.debug("title: %s" % self.title)

        main_window.setObjectName(self.title)
        main_window.setWindowTitle("Hyperion: %s" % self.title)
        self.centralwidget = QtGui.QWidget(main_window)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.verticalLayout = QtGui.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.tabWidget = QtGui.QTabWidget(self.centralwidget)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))

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

        event_manger = self.event_manager = EventManager()
        thread = QtCore.QThread()
        event_manger.crash_signal.connect(self.handle_crash_signal)
        event_manger.crash_signal.connect(self.check_button_callback)
        event_manger.disconnect_signal.connect(self.handle_disconnect_signal)

        event_manger.moveToThread(thread)
        event_manger.done.connect(thread.quit)
        thread.started.connect(partial(event_manger.start, self.control_center))

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

        start_button = BlinkButton('start', self.centralwidget)
        start_button.setObjectName("start_button_all")
        start_button.clicked.connect(lambda: self.handle_start_all())
        start_button.setFocusPolicy(QtCore.Qt.NoFocus)

        stop_button = BlinkButton('stop', self.centralwidget)
        stop_button.setObjectName("stop_button_all")
        stop_button.clicked.connect(lambda: self.handle_stop_all())
        stop_button.setFocusPolicy(QtCore.Qt.NoFocus)

        check_button = BlinkButton('check', self.centralwidget)
        check_button.setObjectName("check_button_all")
        check_button.clicked.connect(lambda: self.handle_check_all())
        check_button.setFocusPolicy(QtCore.Qt.NoFocus)

        spacerItem2 = QtGui.QSpacerItem(20, 5, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)

        container.addWidget(comp_label)
        container.addItem(spacerItem)
        container.addWidget(start_button)
        container.addWidget(stop_button)
        container.addWidget(check_button)
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
        horizontalLayout_components.setObjectName(_fromUtf8("horizontalLayout_%s" % comp['name']))

        comp_label = QtGui.QLabel(scrollAreaWidgetContents)
        comp_label.setObjectName("comp_label_%s" % comp['name'])

        spacerItem = QtGui.QSpacerItem(20, 5, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)

        start_button = BlinkButton('test', scrollAreaWidgetContents)
        start_button.setObjectName("start_button_%s" % comp['name'])
        start_button.setText("start")
        start_button.clicked.connect(lambda: self.handle_start_button(comp))

        stop_button = BlinkButton(scrollAreaWidgetContents)
        stop_button.setObjectName("stop_button_%s" % comp['name'])
        stop_button.setText("stop")
        stop_button.clicked.connect(lambda: self.handle_stop_button(comp))

        check_button = BlinkButton(scrollAreaWidgetContents)
        check_button.setObjectName("check_button_%s" % comp['name'])
        check_button.setText("check")
        check_button.clicked.connect(lambda: self.handle_check_button(comp))

        term_toggle = QtGui.QCheckBox(scrollAreaWidgetContents)
        term_toggle.setObjectName("term_toggle_%s" % comp['name'])
        term_toggle.setText("Show Term")
        term_toggle.stateChanged.connect(lambda: self.handle_term_toggle_state_changed(comp, term_toggle.isChecked()))

        log_toggle = QtGui.QCheckBox(scrollAreaWidgetContents)
        log_toggle.setObjectName("log_toggle_%s" % comp['name'])
        log_toggle.setText("logging")

        log_button = QtGui.QPushButton(scrollAreaWidgetContents)
        log_button.setObjectName("log_button_%s" % comp['name'])
        log_button.setText("view log")
        log_button.clicked.connect(lambda: self.handle_log_button(comp))

        comp_label.raise_()
        comp_label.setText(("%s@%s" % (comp['name'], comp['host'])))

        horizontalLayout_components.addWidget(comp_label)
        horizontalLayout_components.addItem(spacerItem)
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

    def handle_log_button(self, comp):
        """Handles a click on a components log button.

        Opens up an xterm displaying a log file with tail -F.

        :param comp: Component whose log button was clicked
        :type comp: dict
        :return: None
        """

        self.logger.debug("%s show log button pressed" % comp['name'])

        cmd = "tail -n +1 -F %s/%s/latest.log" % (config.TMP_LOG_PATH, comp['name'])

        if self.control_center.run_on_localhost(comp):
            subprocess.Popen(['xterm', '-fg', 'white', '-bg', 'darkblue', '-title', 'log of %s' % comp['name'],
                              '-e', '%s' % cmd], stdout=subprocess.PIPE)

        else:
            subprocess.Popen(['xterm', '-fg', 'white', '-bg', 'darkblue', '-title',
                              'log of %s on %s' % (comp['name'], comp['host']),
                              '-e', "ssh %s -t 'bash -c \"%s\"'" % (comp['host'], cmd)],
                             stdout=subprocess.PIPE)

    def handle_start_all(self):
        """Handles a click on the start all button.

        Starts a worker that runs a dependency based start of all components in a separate thread.
        Also starts an animation for all start buttons tied to the execution of the worker to show the user feedback
        about the running process.

        :return: None
        """

        self.logger.debug("Start all button pressed")

        start_worker = StartWorker()
        thread = QtCore.QThread()
        start_worker.done.connect(self.start_all_callback)
        start_worker.intermediate.connect(self.check_button_callback)

        start_worker.moveToThread(thread)
        start_worker.done.connect(thread.quit)
        thread.started.connect(partial(start_worker.start_all, self.control_center))

        deps = self.control_center.get_start_all_list()
        for dep in deps:
            start_button = self.centralwidget.findChild(QtGui.QPushButton,
                                                        "start_button_%s" % dep.comp_name)  # type: QtGui.QPushButton
            anim = QtCore.QPropertyAnimation(
                start_button,
                "color",
            )

            start_button.setStyleSheet("")

            anim.setDuration(1000)
            anim.setLoopCount(-1)
            anim.setStartValue(QtGui.QColor(255, 255, 255))
            anim.setEndValue(QtGui.QColor(0, 0, 0))
            anim.start()

            self.animations[("start_%s" % dep.comp_name)] = anim

            start_button.setEnabled(False)

        start_button = self.centralwidget.findChild(QtGui.QPushButton,
                                                    "start_button_all")  # type: QtGui.QPushButton
        anim = QtCore.QPropertyAnimation(
            start_button,
            "color",
        )

        start_button.setStyleSheet("")
        start_button.setEnabled(False)

        anim.setDuration(1000)
        anim.setLoopCount(100)
        anim.setStartValue(QtGui.QColor(255, 255, 255))
        anim.setEndValue(QtGui.QColor(0, 0, 0))
        anim.start()

        start_worker.done.connect(lambda: self.threads.remove(thread))
        self.animations["start_all"] = anim

        thread.start()

        # Need to keep a surviving reference to the thread to save it from garbage collection
        self.threads.append(thread)

    def handle_start_button(self, comp):
        """Handles a click on a components start button.

        Starts a worker that runs a dependency based component start in a separate thread. Also starts an animation for
        the clicked button tied to the execution of the worker to show the user feedback about the running process.

        :param comp: Component whose start button was clicked
        :type comp: dict
        :return: None
        """

        self.logger.debug("%s start button pressed" % comp['name'])

        start_worker = StartWorker()
        thread = QtCore.QThread()
        start_worker.done.connect(self.start_button_callback)
        start_worker.intermediate.connect(self.check_button_callback)

        start_worker.moveToThread(thread)
        start_worker.done.connect(thread.quit)
        thread.started.connect(partial(start_worker.run_start, self.control_center, comp))

        deps = self.control_center.get_dep_list(comp)
        for dep in deps:
            start_button = self.centralwidget.findChild(QtGui.QPushButton,
                                                        "start_button_%s" % dep.comp_name)  # type: QtGui.QPushButton
            anim = QtCore.QPropertyAnimation(
                start_button,
                "color",
            )

            start_button.setStyleSheet("")

            anim.setDuration(1000)
            anim.setLoopCount(-1)
            anim.setStartValue(QtGui.QColor(255, 255, 255))
            anim.setEndValue(QtGui.QColor(0, 0, 0))
            anim.start()

            self.animations[("start_%s" % dep.comp_name)] = anim

            start_button.setEnabled(False)

        start_button = self.centralwidget.findChild(QtGui.QPushButton,
                                                    "start_button_%s" % comp['name'])  # type: QtGui.QPushButton
        anim = QtCore.QPropertyAnimation(
            start_button,
            "color",
        )

        start_button.setStyleSheet("")
        start_button.setEnabled(False)

        anim.setDuration(1000)
        anim.setLoopCount(100)
        anim.setStartValue(QtGui.QColor(255, 255, 255))
        anim.setEndValue(QtGui.QColor(0, 0, 0))
        anim.start()

        start_worker.done.connect(lambda: self.threads.remove(thread))
        self.animations[("start_%s" % comp['name'])] = anim

        thread.start()

        # Need to keep a surviving reference to the thread to save it from garbage collection
        self.threads.append(thread)

    def handle_stop_button(self, comp):
        """Handles a click on a components stop button.

        Starts a worker that stops a component in a separate thread and closes a `show term`, if it is active.
        Also starts an animation for the clicked button tied to the execution of the worker to show the user feedback
        about the running process.

        :param comp: Component whose stop button was clicked
        :type comp: dict
        :return: None
        """

        self.logger.debug("%s stop button pressed" % comp['name'])

        if comp['name'] in self.terms:
            term = self.terms[comp['name']]
            if term.poll() is None:
                self.logger.debug("Term %s still running. Trying to kill it" % comp['name'])
                if self.control_center.run_on_localhost(comp):
                    self.control_center.kill_session_by_name("%s-clone-session" % comp['name'])
                else:
                    self.control_center.kill_remote_session_by_name("%s-clone-session" % comp['name'], comp['host'])

        stop_worker = StopWorker()
        thread = QtCore.QThread()
        stop_worker.moveToThread(thread)
        stop_worker.done.connect(thread.quit)
        stop_worker.done.connect(partial(self.handle_check_button, comp))

        thread.started.connect(partial(stop_worker.run_stop, self.control_center, comp))

        stop_button = self.centralwidget.findChild(QtGui.QPushButton,
                                                   "stop_button_%s" % comp['name'])  # type: QtGui.QPushButton
        anim = QtCore.QPropertyAnimation(
            stop_button,
            "color",
        )

        stop_button.setStyleSheet("")
        stop_button.setEnabled(False)

        anim.setDuration(1000)
        anim.setLoopCount(100)
        anim.setStartValue(QtGui.QColor(255, 255, 255))
        anim.setEndValue(QtGui.QColor(0, 0, 0))
        anim.start()

        self.animations[("stop_%s" % comp['name'])] = anim

        thread.start()
        self.threads.append(thread)

        term_toggle = self.centralwidget.findChild(QtGui.QCheckBox, "term_toggle_%s" % comp['name'])
        if term_toggle.isChecked():
            term_toggle.setChecked(False)

    def handle_stop_all(self):
        """Handles a click on the `stop all` button.

        Executes a ``handle_stop_button`` call for each component.

        :return: None
        """

        self.logger.debug("Clicked stop all")
        stop_button = self.centralwidget.findChild(QtGui.QPushButton, "stop_button_all")

        if not self.animations.has_key('stop_all'):
            anim = QtCore.QPropertyAnimation(
                stop_button,
                "color",
            )

            stop_button.setStyleSheet("")

            anim.setDuration(2000)
            anim.setStartValue(QtGui.QColor(0, 0, 0))
            anim.setEndValue(QtGui.QColor(255, 255, 255))
        else:
            anim = self.animations.get('stop_all')

        anim.start()

        self.animations['stop_all'] = anim

        nodes = self.control_center.get_start_all_list()

        for node in nodes:
            self.handle_stop_button(node.component)

    def handle_check_button(self, comp):
        """Handles a click on a components check button.

        Starts a worker that checks a component in a separate thread . Also starts an animation for the clicked button
        tied to the execution of the worker to show the user feedback about the running process.

        :param comp: Component whose check button was clicked
        :type comp: dict
        :return: None
        """

        self.logger.debug("%s check button pressed" % comp['name'])

        check_worker = CheckWorkerThread()
        thread = QtCore.QThread()
        check_worker.check_signal.connect(self.check_button_callback)

        check_worker.moveToThread(thread)
        check_worker.done.connect(thread.quit)
        thread.started.connect(partial(check_worker.run_check, self.control_center, comp))

        check_button = self.centralwidget.findChild(QtGui.QPushButton,
                                                    "check_button_%s" % comp['name'])  # type: QtGui.QPushButton
        anim = QtCore.QPropertyAnimation(
            check_button,
            "color",
        )

        check_button.setStyleSheet("")
        check_button.setEnabled(False)

        anim.setDuration(1000)
        anim.setLoopCount(-1)
        anim.setStartValue(QtGui.QColor(255, 255, 255))
        anim.setEndValue(QtGui.QColor(0, 0, 0))
        anim.start()

        self.animations[("check_%s" % comp['name'])] = anim

        check_worker.check_signal.connect(lambda: self.threads.remove(thread))
        thread.start()

        # Need to keep a surviving reference to the thread to save it from garbage collection
        self.threads.append(thread)

    def handle_check_all(self):
        """Handles a click on the `check all` button.

        Executes a ``handle_check_button`` call for each component.

        :return: None
        """

        self.logger.debug("Clicked check all")
        check_button = self.centralwidget.findChild(QtGui.QPushButton, "check_button_all")

        if not self.animations.has_key('check_all'):
            anim = QtCore.QPropertyAnimation(
                check_button,
                "color",
            )

            check_button.setStyleSheet("")

            anim.setDuration(2000)
            anim.setStartValue(QtGui.QColor(0, 0, 0))
            anim.setEndValue(QtGui.QColor(255, 255, 255))
        else:
            anim = self.animations.get('check_all')

        anim.start()

        self.animations['check_all'] = anim

        nodes = self.control_center.get_start_all_list()

        for node in nodes:
            self.handle_check_button(node.component)

    def handle_term_toggle_state_changed(self, comp, is_checked):
        """Handles toggle or de-toggle of a components show term checkbox.

        Opens or closes an xterm with attached to a components (remote or local) tmux window in a cloned tmux session.

        :param comp: Component whose show term checkbox was clicked
        :type comp: dict
        :param is_checked: Current state of the checkbox
        :type is_checked: bool
        :return: None
        """

        self.logger.debug("%s show term set to: %d" % (comp['name'], is_checked))

        if is_checked:

            if self.control_center.run_on_localhost(comp):
                self.logger.debug("Starting local clone session")
                self.control_center.start_clone_session(comp)

                # Safety wait to ensure clone session is running
                sleep(.5)
                term = subprocess.Popen([("%s" % SCRIPT_SHOW_TERM_PATH),
                                         ("%s-clone-session" % comp['name'])], stdout=subprocess.PIPE)

                self.terms[comp['name']] = term
            else:
                self.logger.debug("Starting remote clone session")
                self.control_center.start_remote_clone_session(comp)

                # Safety wait to ensure clone session is running
                sleep(.5)
                self.logger.debug("Open xterm with ssh")
                term = subprocess.Popen([("%s" % SCRIPT_SHOW_TERM_PATH),
                                         ("%s-clone-session" % comp['name']),
                                         ("%s" % comp['host'])],
                                        stdout=subprocess.PIPE)
                self.terms[comp['name']] = term

        else:
            self.logger.debug("Closing xterm")
            term = self.terms[comp['name']]
            if term.poll() is None:
                self.logger.debug("Term %s still running. Trying to kill it" % comp['name'])

                if self.control_center.run_on_localhost(comp):
                    self.logger.debug("Session '%s' is running locally" % comp['name'])
                    self.control_center.kill_session_by_name("%s-clone-session" % comp['name'])
                else:
                    self.logger.debug("Session '%s' is running on remote host %s" % (comp['name'], comp['host']))
                    self.control_center.kill_remote_session_by_name("%s-clone-session" % comp['name'], comp['host'])
            else:
                self.logger.debug("Term already closed! Command must have crashed. Open log!")

    @QtCore.pyqtSlot(str, int)
    def handle_crash_signal(self, check_status, comp_name):
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

    @QtCore.pyqtSlot(int, str)
    def check_button_callback(self, check_state, comp_name):
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

        check_state = config.CheckState(check_state)

        msg = QtGui.QMessageBox()
        if check_state is config.CheckState.DEP_FAILED:
            msg.setIcon(QtGui.QMessageBox.Warning)
            msg.setText("Start process of '%s' was interrupted" % comp['name'])
            msg.setInformativeText("Dependency '%s' failed!" % failed_name)
            msg.setWindowTitle("Warning")
            msg.setStandardButtons(QtGui.QMessageBox.Retry | QtGui.QMessageBox.Cancel)
            self.logger.debug("Warning, start process of '%s' was interrupted. Dependency '%s' failed!" %
                              (comp['name'], failed_name))
            retval = msg.exec_()

            if retval == QtGui.QMessageBox.Retry:
                self.handle_start_button(comp)

        elif check_state is config.CheckState.STOPPED:
            msg.setIcon(QtGui.QMessageBox.Warning)
            msg.setText("Failed starting '%s'" % comp['name'])
            msg.setWindowTitle("Warning")
            msg.setStandardButtons(QtGui.QMessageBox.Retry | QtGui.QMessageBox.Cancel)
            retval = msg.exec_()

            if retval == QtGui.QMessageBox.Retry:
                self.handle_start_button(comp)
        else:
            self.logger.debug("Starting '%s' succeeded without interference" % comp['name'])
            return

    @QtCore.pyqtSlot(int, dict, str)
    def start_all_callback(self, check_state, comp, failed_name):
        """Handles the done signal of a start all worker thread.

        :param check_state: Final state of the start all process
        :type check_state: int
        :param comp: Unused dummy (provided because the same signal as for a single component start is used)
        :type comp: dict
        :param failed_name: Unused dummy (provided because the same signal as for a single component start is used)
        :type failed_name: str
        :return: None
        """

        check_state = config.CheckState(check_state)

        self.logger.debug("start all callback ended with: %s" % config.STATE_DESCRIPTION.get(check_state))
        start_button = self.centralwidget.findChild(QtGui.QPushButton, "start_button_all")

        if self.animations.has_key("start_all"):
            self.animations.pop("start_all").stop()
        start_button.setEnabled(True)
        start_button.setStyleSheet("")

        if check_state is config.CheckState.RUNNING:
            self.logger.debug("Start all succeeded")
        else:
            start_button.setStyleSheet("background-color: red")
            self.logger.debug("Start all failed")


class EventManager(QtCore.QObject):
    """Class that handles events sent by the main applications monitoring thread."""
    crash_signal = QtCore.pyqtSignal(int, str)
    disconnect_signal = QtCore.pyqtSignal(str)
    done = QtCore.pyqtSignal()

    def __init__(self, parent=None, is_ending=False):
        super(self.__class__, self).__init__(parent)
        self.is_ending = is_ending

    def shutdown(self):
        """Shutown the event manager thread safely by setting the main loop condition to false.

        :return: None
        """

        self.is_ending = True

    @QtCore.pyqtSlot()
    def start(self, control_center):
        """Starts the EventManager main loop and subscribes to the monitoring thread event queue.

        Emits signals to the UI thread to notify it about monitoring events.
        Signals its termination by emitting a ``done`` signal.

        :param control_center: Reference to the core application
        :type control_center: hyperion.ControlCenter
        :return: None
        """

        logger = logging.getLogger(__name__)

        event_queue = queue.Queue()
        control_center.mon_thread.add_subscriber(event_queue)

        while not self.is_ending:
            mon_event = event_queue.get()

            if isinstance(mon_event, DisconnectEvent):
                logger.warning("Got disconnect event from monitoring thread holding message: %s" % mon_event.message)
                logger.debug("Retrying auto reconnect...")
                if not control_center.reconnect_with_host(mon_event.hostname):
                    logger.debug("... Failed! Showing disconnect popup")
                    self.disconnect_signal.emit(mon_event.hostname)
            elif isinstance(mon_event, LocalCrashEvent) or isinstance(mon_event, RemoteCrashEvent):
                logger.warning("Received crash event from monitoring thread holding message: %s" % mon_event.message)
                comp = control_center.get_component_by_name(mon_event.comp_name)
                self.crash_signal.emit((control_center.check_component(comp)).value, mon_event.comp_name)
        self.done.emit()


class CheckWorkerThread(QtCore.QObject):
    done = QtCore.pyqtSignal()
    check_signal = QtCore.pyqtSignal(int, str)

    def __init__(self, parent=None):
        super(self.__class__, self).__init__(parent)

    @QtCore.pyqtSlot()
    def run_check(self, control_center, comp):
        """Runs a component check in the core application.

        Sends an ``check_singal`` signal to notify the UI thread of the component check result and signals its
        termination by sending a ``done`` signal.

        :param control_center: Reference to the core application.
        :type control_center: hyperion.ControlCenter
        :param comp: Component that is being checked
        :type comp: dict
        :return: None
        """

        self.check_signal.emit((control_center.check_component(comp)).value, comp['name'])
        self.done.emit()


class StopWorker(QtCore.QObject):
    done = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super(self.__class__, self).__init__(parent)

    @QtCore.pyqtSlot()
    def run_stop(self, control_center, comp):
        """Stops a component in the core application.

        Signals its termination by sending a ``done`` signal.

        :param control_center: Reference to the core application.
        :type control_center: hyperion.ControlCenter
        :param comp: Component that is being stopped
        :type comp: dict
        :return: None
        """

        logger = logging.getLogger(__name__)
        logger.debug("Running stop")
        control_center.stop_component(comp)
        # Component wait time before check
        logger.debug("Waiting component wait time")
        sleep(control_center.get_component_wait(comp))
        logger.debug("Done stopping")
        self.done.emit()


class StartWorker(QtCore.QObject):
    done = QtCore.pyqtSignal(int, dict, str)
    intermediate = QtCore.pyqtSignal(int, str)

    def __init__(self, parent=None):
        super(self.__class__, self).__init__(parent)

    @QtCore.pyqtSlot()
    def run_start(self, control_center, comp):
        """Starts a component in the core application by starting all of its dependencies first.

        Sends an ``intermediate`` signal for each started component and signals its termination by sending a ``done``
        signal.

        :param control_center: Reference to the core application.
        :type control_center: hyperion.ControlCenter
        :param comp: Component that is being started
        :type comp: dict
        :return: None
        """

        logger = logging.getLogger(__name__)
        comps = control_center.get_dep_list(comp)
        control_center = control_center
        failed = False
        failed_comp = ""

        for dep in comps:
            if not failed:
                logger.debug("Checking dep %s" % dep.comp_name)
                ret = control_center.check_component(dep.component)
                if ret is not config.CheckState.STOPPED:
                    logger.debug("Dep %s already running" % dep.comp_name)
                    self.intermediate.emit(ret.value, dep.comp_name)
                else:
                    tries = 0
                    logger.debug("Starting dep %s" % dep.comp_name)
                    control_center.start_component_without_deps(dep.component)
                    # Component wait time for startup
                    sleep(control_center.get_component_wait(dep.component))
                    while True:
                        sleep(.5)
                        ret = control_center.check_component(dep.component)
                        if (ret is config.CheckState.RUNNING or
                                ret is config.CheckState.STOPPED_BUT_SUCCESSFUL):
                            break
                        if tries > 10 or ret is config.CheckState.NOT_INSTALLED or ret is \
                                config.CheckState.UNREACHABLE:
                            failed = True
                            failed_comp = dep.comp_name
                            ret = config.CheckState.STOPPED
                            break
                        tries = tries + 1
                    self.intermediate.emit(ret.value, dep.comp_name)
            else:
                ret = control_center.check_component(dep.component)
                if ret is not config.CheckState.STOPPED:
                    self.intermediate.emit(ret.value, dep.comp_name)
                else:
                    self.intermediate.emit(config.CheckState.DEP_FAILED.value, dep.comp_name)

        ret = config.CheckState.DEP_FAILED
        if not failed:
            logger.debug("Done starting dependencies. Now starting %s" % comp['name'])
            control_center.start_component_without_deps(comp)

            # Component wait time for startup
            logger.debug("Waiting component startup wait time")
            sleep(control_center.get_component_wait(comp))

            tries = 0
            logger.debug("Running check to ensure start was successful")
            while True:
                sleep(.5)
                ret = control_center.check_component(comp)
                if (ret is config.CheckState.RUNNING or
                    ret is config.CheckState.STOPPED_BUT_SUCCESSFUL or
                    ret is config.CheckState.UNREACHABLE or
                    ret is config.CheckState.NOT_INSTALLED) or tries > 9:
                    break
                logger.debug("Check was not successful. Will retry %s more times before giving up" % (9 - tries))
                tries = tries + 1

        self.intermediate.emit(ret.value, comp['name'])
        self.done.emit(ret.value, comp, failed_comp)

    @QtCore.pyqtSlot()
    def start_all(self, control_center):
        """Starts all components in the core application ordered by dependencies.

        Sends an ``intermediate`` signal for each started component and signals its termination by sending a ``done``
        signal.

        :param control_center: Reference to the core application.
        :type control_center: hyperion.ControlCenter
        :return: None
        """

        logger = logging.getLogger(__name__)
        comps = control_center.get_start_all_list()
        failed = False
        failed_comp = ""
        ret_fail = 0

        for dep in comps:
            if not failed:
                logger.debug("Checking %s" % dep.comp_name)
                ret = control_center.check_component(dep.component)
                if ret is config.CheckState.RUNNING or ret is config.CheckState.STARTED_BY_HAND:
                    logger.debug("Dep %s already running" % dep.comp_name)
                    self.intermediate.emit(ret.value, dep.comp_name)
                else:
                    tries = 0
                    logger.debug("Starting dep %s" % dep.comp_name)
                    control_center.start_component_without_deps(dep.component)
                    # Component wait time for startup
                    sleep(control_center.get_component_wait(dep.component))
                    while True:
                        sleep(.5)
                        ret = control_center.check_component(dep.component)
                        if (ret is config.CheckState.RUNNING or
                                ret is config.CheckState.STOPPED_BUT_SUCCESSFUL):
                            break
                        if tries > 10 or ret is config.CheckState.NOT_INSTALLED or ret is \
                                config.CheckState.UNREACHABLE:
                            failed = True
                            failed_comp = dep.comp_name
                            ret_fail = ret
                            ret = config.CheckState.STOPPED
                            break
                        tries = tries + 1
                    self.intermediate.emit(ret.value, dep.comp_name)
            else:
                ret = control_center.check_component(dep.component)
                if ret is not config.CheckState.STOPPED:
                    self.intermediate.emit(ret.value, dep.comp_name)
                else:
                    self.intermediate.emit(config.CheckState.DEP_FAILED.value, dep.comp_name)

        if failed:
            self.done.emit(ret_fail.value, {}, failed_comp)
        else:
            self.done.emit(config.CheckState.RUNNING.value, {}, 'none')


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
