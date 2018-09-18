#from hyperion import ControlCenter
from PyQt4 import QtCore, QtGui
import logging

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

        self.control_center = control_center #type: ControlCenter
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
                verticalLayout_compList.addLayout(create_component(component, scrollAreaWidgetContents))

            scrollArea.setWidget(scrollAreaWidgetContents)
            horizontalLayout.addWidget(scrollArea)
            self.tabWidget.addTab(groupTab, group['name'])


def create_component(comp, scrollAreaWidgetContents):
    horizontalLayout_components = QtGui.QHBoxLayout()
    horizontalLayout_components.setObjectName(_fromUtf8("horizontalLayout_%s" % comp['name']))

    comp_label = QtGui.QLabel(scrollAreaWidgetContents)
    comp_label.setObjectName(_fromUtf8("comp_label"))
    horizontalLayout_components.addWidget(comp_label)
    spacerItem = QtGui.QSpacerItem(200, 44, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
    horizontalLayout_components.addItem(spacerItem)
    start_button = QtGui.QPushButton(scrollAreaWidgetContents)
    start_button.setObjectName(_fromUtf8("start_button"))
    horizontalLayout_components.addWidget(start_button)
    stop_button = QtGui.QPushButton(scrollAreaWidgetContents)
    stop_button.setObjectName(_fromUtf8("stop_button"))
    horizontalLayout_components.addWidget(stop_button)
    check_button = QtGui.QPushButton(scrollAreaWidgetContents)
    check_button.setObjectName(_fromUtf8("check_button"))
    horizontalLayout_components.addWidget(check_button)
    term_toggle = QtGui.QCheckBox(scrollAreaWidgetContents)
    term_toggle.setObjectName(_fromUtf8("term_toggle"))
    horizontalLayout_components.addWidget(term_toggle)
    log_toggle = QtGui.QCheckBox(scrollAreaWidgetContents)
    log_toggle.setObjectName(_fromUtf8("log_toggle"))
    horizontalLayout_components.addWidget(log_toggle)
    log_button = QtGui.QPushButton(scrollAreaWidgetContents)
    log_button.setObjectName(_fromUtf8("log_button"))
    horizontalLayout_components.addWidget(log_button)
    comp_label.raise_()

    comp_label.setText(("%s@%s" % (comp['name'], comp['host'])))
    start_button.setText("start")
    stop_button.setText("stop")
    check_button.setText("check")
    term_toggle.setText("Show Term")
    log_toggle.setText("logging")
    log_button.setText("view log")

    return horizontalLayout_components