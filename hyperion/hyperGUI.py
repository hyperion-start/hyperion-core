import hyperion
from PyQt4 import QtCore, QtGui
import os
import subprocess
import logging
from functools import partial
from time import sleep
from DepTree import Node

BASE_DIR = os.path.dirname(__file__)
SCRIPT_CLONE_PATH = ("%s/scripts/start_named_clone_session.sh" % BASE_DIR)
SCRIPT_SHOW_TERM_PATH = ("%s/scripts/show_term.sh" % BASE_DIR)

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

        self.control_center = control_center #type: hyperion.ControlCenter
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
        start_button.clicked.connect(lambda: self.handleStartButton(comp))

        stop_button = QtGui.QPushButton(scrollAreaWidgetContents)
        stop_button.setObjectName("stop_button_%s" % comp['name'])
        stop_button.setText("stop")
        stop_button.clicked.connect(lambda: self.handleStopButton(comp))

        check_button = BlinkButton(scrollAreaWidgetContents)
        check_button.setObjectName("check_button_%s" % comp['name'])
        check_button.setText("check")
        check_button.clicked.connect(lambda: self.handleCheckButton(comp))

        term_toggle = QtGui.QCheckBox(scrollAreaWidgetContents)
        term_toggle.setObjectName("term_toggle_%s" % comp['name'])
        term_toggle.setText("Show Term")
        term_toggle.stateChanged.connect(lambda: self.handleTermToggleStateChanged(comp, term_toggle.isChecked()))

        log_toggle = QtGui.QCheckBox(scrollAreaWidgetContents)
        log_toggle.setObjectName("log_toggle_%s" % comp['name'])
        log_toggle.setText("logging")

        log_button = QtGui.QPushButton(scrollAreaWidgetContents)
        log_button.setObjectName("log_button_%s" % comp['name'])
        log_button.setText("view log")

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

    def handleStartButton(self, comp):
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

    def handleStopButton(self, comp):
        self.logger.debug("%s stop button pressed" % comp['name'])
        self.control_center.stop_component(comp)

        if comp['name'] in self.terms:
            term = self.terms[comp['name']]
            if term.poll() is None:
                self.logger.debug("Term %s still running. Trying to kill it" % comp['name'])
                hyperion.kill_session_by_name(self.control_center.server, "%s-clone-session" % comp['name'])

        self.handleCheckButton(comp)

        term_toggle = self.centralwidget.findChild(QtGui.QCheckBox, "term_toggle_%s" % comp['name'])
        if term_toggle.isChecked():
            term_toggle.setChecked(False)

    def handleCheckButton(self, comp):
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

    def handleTermToggleStateChanged(self, comp, isChecked):
        self.logger.debug("%s show term set to: %d" % (comp['name'], isChecked))
        if isChecked:
            p = subprocess.Popen([("%s" % SCRIPT_CLONE_PATH), ("%s" % self.title), ("%s" % comp['name'])], stdout=subprocess.PIPE)
            out, err = p.communicate()
            self.logger.debug(out)

            self.logger.debug("%s '%s' '%s'" % (SCRIPT_CLONE_PATH, self.title, comp['name']))

            term = subprocess.Popen([("%s" % SCRIPT_SHOW_TERM_PATH), ("'%s-clone-session'" % comp['name'])], stdout=subprocess.PIPE)
            self.terms[comp['name']] = term

        else:
            self.logger.debug("Closing xterm")
            term = self.terms[comp['name']]
            if term.poll() is None:
                self.logger.debug("Term %s still running. Trying to kill it" % comp['name'])
                hyperion.kill_session_by_name(self.control_center.server, "%s-clone-session" % comp['name'])
            else:
                self.logger.debug("Term already closed! Command must have crashed. Open log!")

    @QtCore.pyqtSlot(int, str)
    def check_button_callback(self, check_state, comp_name):
        check_button = self.centralwidget.findChild(QtGui.QPushButton, "check_button_%s" % comp_name)

        if check_state is hyperion.CheckState.STOPPED.value:
            check_button.setStyleSheet("background-color: red")
        elif check_state is hyperion.CheckState.RUNNING.value:
            check_button.setStyleSheet("background-color: green")
        elif check_state is hyperion.CheckState.STARTED_BY_HAND.value:
            check_button.setStyleSheet("background-color: lightsalmon")
        elif check_state is hyperion.CheckState.STOPPED_BUT_SUCCESSFUL.value:
            check_button.setStyleSheet("background-color: darkcyan")
        elif check_state is hyperion.CheckState.DEP_FAILED.value:
            check_button.setStyleSheet("background-color: darkred")

        check_button.setEnabled(True)

        if self.animations.has_key("start_%s" % comp_name):
            self.animations.pop("start_%s" % comp_name).stop()
            start_button = self.centralwidget.findChild(QtGui.QPushButton, "start_button_%s" % comp_name)
            start_button.setColor(QtGui.QColor(255,255,255))
            start_button.setEnabled(True)

        if self.animations.has_key("check_%s" % comp_name):
            self.animations.pop("check_%s" % comp_name).stop()
            check_button.setColor(QtGui.QColor(255,255,255))

    @QtCore.pyqtSlot(int, dict, str)
    def start_button_callback(self, check_state, comp, failed_name):

        msg = QtGui.QMessageBox()
        if check_state is hyperion.CheckState.DEP_FAILED.value:
            msg.setIcon(QtGui.QMessageBox.Warning)
            msg.setText("Start process of '%s' was interrupted" % comp['name'])
            msg.setInformativeText("Dependency '%s' failed!" % failed_name)
            msg.setWindowTitle("Warning")
            msg.setStandardButtons(QtGui.QMessageBox.Retry | QtGui.QMessageBox.Cancel)
            self.logger.debug("Warning, start process of '%s' was interrupted. Dependency '%s' failed!" %
                              (comp['name'], failed_name))
            retval = msg.exec_()

            if retval == QtGui.QMessageBox.Retry:
                self.handleStartButton(comp)

        elif check_state is hyperion.CheckState.STOPPED.value:
            msg.setIcon(QtGui.QMessageBox.Warning)
            msg.setText("Failed starting '%s'" % comp['name'])
            msg.setWindowTitle("Warning")
            msg.setStandardButtons(QtGui.QMessageBox.Retry | QtGui.QMessageBox.Cancel)
            retval = msg.exec_()

            if retval == QtGui.QMessageBox.Retry:
                self.handleStartButton(comp)
        else:
            self.logger.debug("Starting '%s' succeeded without interference")
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

        print("Checking deps")
        for dep in comps:
            if not failed:
                logger.debug("Checking dep %s" % dep.comp_name)
                ret = control_center.check_component(dep.component)
                if ret is not hyperion.CheckState.STOPPED:
                    logger.debug("Dep %s already running" % dep.comp_name)
                    self.intermediate.emit(ret.value, dep.comp_name)
                else:
                    tries = 0
                    logger.debug("Starting dep %s" % dep.comp_name)
                    control_center.start_component_without_deps(dep.component)
                    while True:
                        sleep(.5)
                        ret = control_center.check_component(dep.component)
                        if (ret is hyperion.CheckState.RUNNING or
                                ret is hyperion.CheckState.STOPPED_BUT_SUCCESSFUL):
                            break
                        if tries > 10:
                            failed = True
                            failed_comp = dep.comp_name
                            ret = hyperion.CheckState.STOPPED
                            break
                        tries = tries + 1
                    self.intermediate.emit(ret.value, dep.comp_name)
            else:
                ret = control_center.check_component(dep.component)
                if ret is not hyperion.CheckState.STOPPED:
                    self.intermediate.emit(ret.value, dep.comp_name)
                else:
                    self.intermediate.emit(hyperion.CheckState.DEP_FAILED.value, dep.comp_name)

        ret = hyperion.CheckState.DEP_FAILED
        if not failed:
            logger.debug("Done starting")
            control_center.start_component_without_deps(comp)
            ret = control_center.check_component(comp)

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
