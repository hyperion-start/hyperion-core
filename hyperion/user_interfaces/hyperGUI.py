import hyperion.manager as manager
from PyQt4 import QtCore, QtGui
import os
import subprocess
import logging
from functools import partial
from time import sleep

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

    def ui_init(self, main_window, control_center):

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.terms = {}
        self.threads = []
        self.animations = {}

        self.control_center = control_center #type: manager.ControlCenter
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

        self.verticalLayout.addWidget(self.tabWidget)
        main_window.setCentralWidget(self.centralwidget)
        self.tabWidget.setCurrentIndex(0)

    def create_tabs(self):
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
            for component in group['components']:
                verticalLayout_compList.addLayout(self.create_component(component, scrollAreaWidgetContents))

            scrollArea.setWidget(scrollAreaWidgetContents)
            horizontalLayout.addWidget(scrollArea)
            self.tabWidget.addTab(groupTab, group['name'])

    def create_component(self, comp, scrollAreaWidgetContents):
        horizontalLayout_components = QtGui.QHBoxLayout()
        horizontalLayout_components.setObjectName(_fromUtf8("horizontalLayout_%s" % comp['name']))

        comp_label = QtGui.QLabel(scrollAreaWidgetContents)
        comp_label.setObjectName("comp_label_%s" % comp['name'])

        spacerItem = QtGui.QSpacerItem(200, 44, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)

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
        log_button.clicked.connect(lambda: self.handleLogButton(comp))

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

    def handleLogButton(self, comp):
        self.logger.debug("%s show log button pressed" % comp['name'])

        cmd = "tail -n +1 -f %s/%s/latest.log" % (manager.TMP_LOG_PATH, comp['name'])

        if self.control_center.run_on_localhost(comp):
            term = subprocess.Popen(['xterm', '-e', '%s' % cmd], stdout=subprocess.PIPE)

        else:
            term = subprocess.Popen(['xterm', '-e', "ssh %s -t 'bash -c \"%s\"'" % (comp['host'], cmd)],
                                    stdout=subprocess.PIPE)

    def handle_start_button(self, comp):
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
        self.logger.debug("%s stop button pressed" % comp['name'])

        if comp['name'] in self.terms:
            term = self.terms[comp['name']]
            if term.poll() is None:
                self.logger.debug("Term %s still running. Trying to kill it" % comp['name'])
                self.control_center.kill_session_by_name("%s-clone-session" % comp['name'])

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

    def handle_check_button(self, comp):
        self.logger.debug("%s check button pressed" % comp['name'])

        check_worker = CheckWorkerThread()
        thread = QtCore.QThread()
        check_worker.check_signal.connect(self.check_button_callback)

        check_worker.moveToThread(thread)
        check_worker.done.connect(thread.quit)
        thread.started.connect(partial(check_worker.run_check, self.control_center, comp))

        check_button = self.centralwidget.findChild(QtGui.QPushButton, "check_button_%s" % comp['name'])#type: QtGui.QPushButton
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

    def handle_term_toggle_state_changed(self, comp, is_checked):
        self.logger.debug("%s show term set to: %d" % (comp['name'], is_checked))

        if is_checked:

            if self.control_center.run_on_localhost(comp):
                self.logger.debug("Starting local clone session")
                self.control_center.start_clone_session(comp['name'], self.title)

                # Safety wait to ensure clone session is running
                sleep(.5)
                term = subprocess.Popen([("%s" % SCRIPT_SHOW_TERM_PATH),
                                         ("%s-clone-session" % comp['name'])], stdout=subprocess.PIPE)
                
                self.terms[comp['name']] = term
            else:
                self.logger.debug("Starting remote clone session")
                self.control_center.start_remote_clone_session(comp['name'], 'slave-session', comp['host'])

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

    @QtCore.pyqtSlot(int, str)
    def check_button_callback(self, check_state, comp_name):
        check_button = self.centralwidget.findChild(QtGui.QPushButton, "check_button_%s" % comp_name)

        if check_state is manager.CheckState.STOPPED.value:
            check_button.setStyleSheet("background-color: red")
        elif check_state is manager.CheckState.RUNNING.value:
            check_button.setStyleSheet("background-color: green")
        elif check_state is manager.CheckState.STARTED_BY_HAND.value:
            check_button.setStyleSheet("background-color: lightsalmon")
        elif check_state is manager.CheckState.STOPPED_BUT_SUCCESSFUL.value:
            check_button.setStyleSheet("background-color: darkcyan")
        elif check_state is manager.CheckState.DEP_FAILED.value:
            check_button.setStyleSheet("background-color: darkred")
        elif check_state is manager.CheckState.NOT_INSTALLED.value:
            check_button.setStyleSheet("background-color: red")

            msg = QtGui.QMessageBox()
            msg.setIcon(QtGui.QMessageBox.Critical)
            msg.setText("Failed on '%s': Hyperion is not installed on remote host!" % comp_name)
            msg.setWindowTitle("Error")
            msg.setStandardButtons(QtGui.QMessageBox.Close)

            msg.exec_()

        elif check_state is manager.CheckState.UNREACHABLE.value:
            check_button.setStyleSheet("background-color: red")

            msg = QtGui.QMessageBox()
            msg.setIcon(QtGui.QMessageBox.Critical)
            msg.setText("Failed on '%s': Remote host not reachable!" % comp_name)
            msg.setWindowTitle("Error")
            msg.setStandardButtons(QtGui.QMessageBox.Close)

            msg.exec_()

        check_button.setEnabled(True)

        if self.animations.has_key("start_%s" % comp_name):
            self.animations.pop("start_%s" % comp_name).stop()
            start_button = self.centralwidget.findChild(QtGui.QPushButton, "start_button_%s" % comp_name)
            start_button.setColor(QtGui.QColor(255,255,255))
            start_button.setEnabled(True)

        if self.animations.has_key("check_%s" % comp_name):
            self.animations.pop("check_%s" % comp_name).stop()
            check_button.setColor(QtGui.QColor(255,255,255))

        if self.animations.has_key("stop_%s" % comp_name):
            self.animations.pop("stop_%s" % comp_name).stop()
            stop_button = self.centralwidget.findChild(QtGui.QPushButton, "stop_button_%s" % comp_name)
            stop_button.setColor(QtGui.QColor(255,255,255))
            stop_button.setEnabled(True)

    @QtCore.pyqtSlot(int, dict, str)
    def start_button_callback(self, check_state, comp, failed_name):

        msg = QtGui.QMessageBox()
        if check_state is manager.CheckState.DEP_FAILED.value:
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

        elif check_state is manager.CheckState.STOPPED.value:
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


class CheckWorkerThread(QtCore.QObject):
    done = QtCore.pyqtSignal()
    check_signal = QtCore.pyqtSignal(int, str)

    def __init__(self, parent=None):
        super(self.__class__, self).__init__(parent)

    @QtCore.pyqtSlot()
    def run_check(self, control_center, comp):
        self.check_signal.emit((control_center.check_component(comp)).value, comp['name'])
        self.done.emit()


class StopWorker(QtCore.QObject):
    done = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super(self.__class__, self).__init__(parent)

    @QtCore.pyqtSlot()
    def run_stop(self, control_center, comp):
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
        logger = logging.getLogger(__name__)
        comps = control_center.get_dep_list(comp)
        control_center = control_center
        failed = False
        failed_comp = ""

        for dep in comps:
            if not failed:
                logger.debug("Checking dep %s" % dep.comp_name)
                ret = control_center.check_component(dep.component)
                if ret is not manager.CheckState.STOPPED:
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
                        if (ret is manager.CheckState.RUNNING or
                                ret is manager.CheckState.STOPPED_BUT_SUCCESSFUL):
                            break
                        if tries > 10 or ret is manager.CheckState.NOT_INSTALLED or ret is \
                                manager.CheckState.UNREACHABLE:
                            failed = True
                            failed_comp = dep.comp_name
                            ret = manager.CheckState.STOPPED
                            break
                        tries = tries + 1
                    self.intermediate.emit(ret.value, dep.comp_name)
            else:
                ret = control_center.check_component(dep.component)
                if ret is not manager.CheckState.STOPPED:
                    self.intermediate.emit(ret.value, dep.comp_name)
                else:
                    self.intermediate.emit(manager.CheckState.DEP_FAILED.value, dep.comp_name)

        ret = manager.CheckState.DEP_FAILED
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
                if (ret is manager.CheckState.RUNNING or
                        ret is manager.CheckState.STOPPED_BUT_SUCCESSFUL or
                        ret is manager.CheckState.UNREACHABLE or
                        ret is manager.CheckState.NOT_INSTALLED) or tries > 9:
                    break
                logger.debug("Check was not successful. Will retry %s more times before giving up" % (9 - tries))
                tries = tries + 1

        self.intermediate.emit(ret.value, comp['name'])
        self.done.emit(ret.value, comp, failed_comp)


class BlinkButton(QtGui.QPushButton):
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
