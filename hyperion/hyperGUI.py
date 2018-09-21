import hyperion
from PyQt4 import QtCore, QtGui
import os
import subprocess
import logging

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
        comp_label.setObjectName(_fromUtf8("comp_label"))

        spacerItem = QtGui.QSpacerItem(200, 44, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)

        start_button = QtGui.QPushButton('test', scrollAreaWidgetContents)
        start_button.setObjectName(_fromUtf8("start_button"))
        start_button.setText("start")
        start_button.clicked.connect(lambda: self.handleStartButton(comp))

        stop_button = QtGui.QPushButton(scrollAreaWidgetContents)
        stop_button.setObjectName(_fromUtf8("stop_button"))
        stop_button.setText("stop")
        stop_button.clicked.connect(lambda: self.handleStopButton(comp))

        check_button = QtGui.QPushButton(scrollAreaWidgetContents)
        check_button.setObjectName(_fromUtf8("check_button"))
        check_button.setText("check")
        check_button.clicked.connect(lambda: self.handleCheckButton(comp))

        term_toggle = QtGui.QCheckBox(scrollAreaWidgetContents)
        term_toggle.setObjectName(_fromUtf8("term_toggle"))
        term_toggle.setText("Show Term")
        term_toggle.stateChanged.connect(lambda: self.handleTermToggleStateChanged(comp, term_toggle.isChecked()))

        log_toggle = QtGui.QCheckBox(scrollAreaWidgetContents)
        log_toggle.setObjectName(_fromUtf8("log_toggle"))
        log_toggle.setText("logging")

        log_button = QtGui.QPushButton(scrollAreaWidgetContents)
        log_button.setObjectName(_fromUtf8("log_button"))
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

        return horizontalLayout_components

    def handleStartButton(self, comp):
        self.logger.debug("%s start button pressed" % comp['name'])
        self.control_center.start_component(comp)

    def handleStopButton(self, comp):
        self.logger.debug("%s stop button pressed" % comp['name'])
        self.control_center.stop_component(comp)

        term = self.terms[comp['name']]
        if term.poll() is None:
            self.logger.debug("Term %s still running. Trying to kill it" % comp['name'])
            hyperion.kill_session_by_name(self.control_center.server, "%s-clone-session" % comp['name'])

        #TODO: maybe add term checkbox as arg to unset on stop?

    def handleCheckButton(self, comp):
        self.logger.debug("%s check button pressed. NYI!" % comp['name'])

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