import hyperion
from PyQt4 import QtCore, QtGui
import os
import subprocess
import logging
from functools import partial

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
        self.animations = []

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

        start_button = QtGui.QPushButton('test', scrollAreaWidgetContents)
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
        self.control_center.start_component(comp)

    def handleStopButton(self, comp):
        self.logger.debug("%s stop button pressed" % comp['name'])
        self.control_center.stop_component(comp)

        if comp['name'] in self.terms:
            term = self.terms[comp['name']]
            if term.poll() is None:
                self.logger.debug("Term %s still running. Trying to kill it" % comp['name'])
                hyperion.kill_session_by_name(self.control_center.server, "%s-clone-session" % comp['name'])

        self.handleCheckButton(comp)
        #TODO: maybe add term checkbox as arg to unset on stop?

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

        anim.setDuration(1000)
        anim.setLoopCount(100)
        anim.setStartValue(QtGui.QColor(255, 255, 255))
        anim.setEndValue(QtGui.QColor(0, 0, 0))
        anim.start()

        check_worker.check_signal.connect(anim.stop)
        check_worker.check_signal.connect(lambda: (self.animations.remove(anim), self.threads.remove(thread)))
        self.animations.append(anim)

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
        if check_state is hyperion.CheckState.RUNNING.value:
            check_button.setStyleSheet("background-color: green")
        if check_state is hyperion.CheckState.STARTED_BY_HAND.value:
            check_button.setStyleSheet("background-color: lightsalmon")
        if check_state is hyperion.CheckState.STOPPED_BUT_SUCCESSFUL.value:
            check_button.setStyleSheet("background-color: darkcyan")

class CheckWorkerThread(QtCore.QObject):
    done = QtCore.pyqtSignal()
    check_signal = QtCore.pyqtSignal(int, str)

    def __init__(self, parent=None):
        super(self.__class__, self).__init__(parent)

    @QtCore.pyqtSlot()
    def run_check(self, control_center, comp):
        self.check_signal.emit((control_center.check_component(comp)).value, comp['name'])
        self.done.emit()


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
