import unittest
import manager
import libtmux
import lib.util.exception
import os.path
import time
import sys
import hyperion.lib.util.exception as exceptions
import hyperion.lib.util.config as config
from hyperion.lib.monitoring.threads import *

is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as queue
else:
    import queue as queue


class BasicManagerTests(unittest.TestCase):
    def setUp(self):
        self.cc = manager.ControlCenter('%s/data/test-config.yaml' % manager.BASE_DIR)
        self.cc.init()

    def tearDown(self):
        try:
            self.cc.cleanup(True)
        except SystemExit:
            pass

    def test_construction(self):
        self.assertEqual(self.cc.config['name'], 'Unit test config')
        self.assertTrue(self.cc.server.has_session('Unit test config'))

    def test_initialization(self):
        self.assertTrue('id' in self.cc.config['groups'][0]['components'][0])

    def test_component_fetch(self):
        tail = self.cc.get_component_by_id('tail@localhost')
        self.assertEqual(tail['name'], 'tail')
        with self.assertRaises(lib.util.exception.ComponentNotFoundException):
            self.cc.get_component_by_id('do fail')

        lst = self.cc.get_start_all_list()
        self.assertEqual(lst[0].comp_id, 'tail@localhost')

        wait = manager.get_component_wait(tail)
        self.assertEqual(wait, 0.2)

    def test_non_full_shutdown(self):
        try:
            self.cc.cleanup()
        except SystemExit:
            pass
        self.assertTrue(self.cc.server.has_session(self.cc.session_name))

    def test_setting_up_log(self):
        window = self.cc.session.new_window('unit test')
        log_file = '/tmp/Hyperion/unit-test/test.log'
        manager.setup_log(window, log_file, 'unit test', True)
        window.cmd("send-keys", 'ls', "Enter")
        self.cc._wait_until_window_not_busy(window)
        # Wait for log to be created
        time.sleep(.1)
        self.assertTrue(os.path.isfile(log_file))

    def test_missing_dep(self):
        self.cc.config['groups'][0]['components'][0]['depends'][0] = 'dependency@missing'
        with self.assertRaises(exceptions.UnmetDependenciesException):
            self.cc.set_dependencies()

    def test_circular_dep(self):
        self.cc.config['groups'][1]['components'][1]['depends'] = ['top@localhost']
        with self.assertRaises(exceptions.CircularReferenceException):
            self.cc.set_dependencies()

    def test_full_shutdown(self):
        try:
            self.cc.cleanup(True)
        except SystemExit:
            pass
        server = libtmux.Server()
        self.assertFalse(server.has_session(self.cc.session_name))

        # Restore for tearDown()
        self.cc = manager.ControlCenter('%s/data/test-config.yaml' % manager.BASE_DIR)


class ComponentTest(unittest.TestCase):

    def setUp(self):
        self.cc = manager.ControlCenter('%s/data/test-config.yaml' % manager.BASE_DIR, True)
        self.cc.init()
        self.tail = self.cc.get_component_by_id('tail@localhost')
        self.ls = self.cc.get_component_by_id('ls@localhost')
        self.top = self.cc.get_component_by_id('top@localhost')

    def tearDown(self):
        try:
            self.cc.cleanup(True)
        except SystemExit:
            pass

    def test_single_component_functions(self):
        self.cc.start_component_without_deps(self.tail)
        self.assertFalse(self.cc._find_window(self.tail['id']) is None)

        self.assertEqual(self.cc.check_component(self.tail), config.CheckState.RUNNING)

        self.cc.stop_component(self.tail)
        self.assertEqual(self.cc.check_component(self.tail), config.CheckState.STOPPED)

    def test_environment_loading(self):
        window = self.cc.session.new_window('unit test')
        self.cc._start_window(window, self.ls, '/tmp/Hyperion/unit-test/test.log')
        window.cmd('send-keys', '$env_test', 'Enter')
        time.sleep(0.2)
        self.assertFalse(self.cc._find_window('unit test'))

    def test_multi_start(self):
        self.cc.start_component_without_deps(self.tail)
        time.sleep(0.3)
        self.cc.start_component_without_deps(self.tail)

        ret = self.cc.check_component(self.tail)
        self.assertEqual(ret, config.CheckState.RUNNING)

    def test_check_states(self):
        self.assertEqual(self.cc.check_component(self.ls), config.CheckState.STARTED_BY_HAND)

        self.cc.start_component_without_deps(self.tail)
        window = self.cc._find_window(self.tail['id'])
        window.cmd('send-keys', '', 'C-c')

        window = self.cc.session.new_window('unit test')
        window.cmd("send-keys", 'tail', "Enter")
        time.sleep(0.4)
        self.assertEqual(self.cc.check_component(self.tail), config.CheckState.STOPPED_BUT_SUCCESSFUL)

    def test_dep_list(self):
        lst = self.cc.get_dep_list(self.top)
        self.assertEqual(lst[0].component, self.tail)

    def test_monitoring_queue(self):
        ev_queue = queue.Queue()
        self.cc.add_subscriber(ev_queue)
        self.cc.start_component_without_deps(self.tail)
        self.cc.check_component(self.tail)
        window = self.cc._find_window(self.tail['id'])
        window.cmd('send-keys', '', 'C-c')
        time.sleep(1)
        self.assertFalse(ev_queue.empty())

        # Start event
        msg = ev_queue.get()
        self.assertTrue(isinstance(msg, events.StartingEvent))
        self.assertEqual(msg.comp_id, 'tail@localhost')

        # Check event
        msg = ev_queue.get()
        self.assertTrue(isinstance(msg, events.CheckEvent))
        self.assertEqual(msg.comp_id, 'tail@localhost')

        msg = ev_queue.get()
        self.assertTrue(isinstance(msg, events.CrashEvent))
        self.assertEqual(msg.comp_id, 'tail@localhost')


class ExecuteModeTest(unittest.TestCase):

    def setUp(self):
        self.cc = manager.ControlCenter('%s/data/test-config.yaml' % manager.BASE_DIR)
        self.cc.init()

    def tearDown(self):
        try:
            self.cc.cleanup(True)
        except SystemExit:
            pass

    def test_start(self):
        self.cc.start_by_cli('tail@localhost')
        self.assertEqual(
            self.cc.check_component(self.cc.get_component_by_id('tail@localhost')), config.CheckState.RUNNING
        )

    def test_stop(self):
        self.cc.start_by_cli('tail@localhost')
        self.assertEqual(
            self.cc.check_component(self.cc.get_component_by_id('tail@localhost')), config.CheckState.RUNNING
        )

        self.cc.stop_by_cli('tail@localhost')
        self.assertEqual(
            self.cc.check_component(self.cc.get_component_by_id('tail@localhost')), config.CheckState.STOPPED
        )


if __name__ == '__main__':
    unittest.main()
