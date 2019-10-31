import socket
import select
import time
import logging
import logging.handlers
import sys
import struct
import threading
import hyperion.manager
from signal import *
import hyperion.lib.util.depTree
import hyperion.lib.util.actionSerializer as actionSerializer
import hyperion.lib.util.exception as exceptions
import hyperion.lib.util.events as events
import hyperion.lib.util.config as config

is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as queue
else:
    import queue as queue

try:
    import selectors
except ImportError:
    logging.warn("Module selectors not found! Trying to load selectors2")
    try:
        import selectors2 as selectors
    except ImportError as err:
        logging.critical("Neither selectors or selectors2 is installed. You need one of these packages to run hyperion! Err: %s" % err)
        raise err


def recvall(connection, n):
    """Helper function to recv n bytes or return None if EOF is hit

    To read a message with an expected size and combine it to one object, even if it was split into more than one
    packets.

    :param connection: Connection to a socket
    :param n: Size of the message to read in bytes
    :type n: int
    :return: Expected message combined into one string
    """

    data = b''
    while len(data) < n:
        packet = connection.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


class BaseServer(object):
    """Base class for servers."""
    def __init__(self):
        self.port = None
        self.sel = selectors.DefaultSelector()
        self.keep_running = True
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(config.DEFAULT_LOG_LEVEL)
        self.send_queues = {}
        signal(SIGINT, self._handle_sigint)

    def accept(self, sock, mask):
        """Callback for new connections"""
        new_connection, addr = sock.accept()
        self.logger.debug('accept({})'.format(addr))
        new_connection.setblocking(False)
        self.send_queues[new_connection] = queue.Queue()
        self.sel.register(new_connection, selectors.EVENT_READ | selectors.EVENT_WRITE)

    def _interpret_message(self, action, args, connection):
        raise NotImplementedError

    def write(self, connection):
        """Callback for write events"""
        send_queue = self.send_queues.get(connection)
        if send_queue and not send_queue.empty() and self.keep_running:
            # Messages available
            next_msg = send_queue.get()
            try:
                connection.sendall(next_msg)
            except socket.error as err:
                self.logger.error("Error while writing message to socket: %s" % err)

    def read(self, connection):
        raise NotImplementedError

    def _handle_sigint(self, signum, frame):
        self.logger.debug("Received C-c")
        self._quit()

    def _quit(self):
        self.logger.debug("Sending all pending messages to slave clients before quitting server...")
        for sub in self.send_queues:
            while self.send_queues.get(sub) and not self.send_queues.get(sub).empty():
                time.sleep(0.5)
        self.logger.debug("... All pending messages sent to slave clients!")
        self.send_queues = {}
        self.keep_running = False


class Server(BaseServer):
    def __init__(self, port, cc, loop_in_thread=False):
        BaseServer.__init__(self)
        self.port = port
        self.cc = cc  # type: hyperion.ControlCenter
        self.event_queue = queue.Queue()
        self.cc.add_subscriber(self.event_queue)

        server_address = ('localhost', port)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.setblocking(False)
        try:
            server.bind(server_address)
            self.logger.debug("Starting server on localhost:%s" % server.getsockname()[1])
        except socket.error as e:
            if e.errno == 98:
                self.logger.critical("Server adress '%s' is already in use! Try waiting a few seconds if you are sure "
                                     "there is no other instance running" % (server_address,))
                # Simulate sigint
                self._handle_sigint(None, None)
            else:
                self.logger.critical("Error while trying to bind server adress: %s" % e)
                self._handle_sigint(None, None)
        server.listen(5)

        self.function_mapping = {
            'start_all': self.cc.start_all,
            'start': self._start_component_wrapper,
            'check': self._check_component_wrapper,
            'stop_all': self.cc.stop_all,
            'stop': self._stop_component_wrapper,
            'get_conf': self._send_config,
            'get_host_list': self._send_host_list,
            'get_host_stats': self._send_host_stats,
            'quit': self.cc.cleanup,
            'reconnect_with_host': self.cc.reconnect_with_host,
            'unsubscribe': None,
            'reload_config': self.cc.reload_config,
            'start_clone_session': self._handle_start_clone_session
        }

        self.receiver_mapping = {
            'get_conf': 'single',
            'get_host_list': 'single',
            'get_host_stats': 'single'
        }

        self.sel.register(server, selectors.EVENT_READ, self.accept)

        if not loop_in_thread:
            self._loop()
        else:
            self.worker = worker = threading.Thread(target=self._loop)
            worker.start()

    def _loop(self):
        while self.keep_running:
            try:
                for key, mask in self.sel.select(timeout=1):
                    connection = key.fileobj
                    if key.data and self.keep_running:
                        callback = key.data
                        callback(connection, mask)

                    else:
                        if mask & selectors.EVENT_READ:
                            self.read(connection)
                        if mask & selectors.EVENT_WRITE:
                            self.write(connection)
                self._process_events()
                time.sleep(0.3)
            except OSError:
                self.logger.error("Caught timeout exception while reading from/writing to ui clients. "
                                  "If this error occured during shutdown, everything is in order!")
                pass

        self.logger.debug('Exited messaging loop')
        self.sel.close()

    def read(self, connection):
        """Callback for read events"""
        try:
            raw_msglen = connection.recv(4)
            if raw_msglen:
                # A readable client socket has data
                msglen = struct.unpack('>I', raw_msglen)[0]
                data = recvall(connection, msglen)
                self.logger.debug("Received message")
                action, args = actionSerializer.deserialize(data)

                if action:
                    worker = threading.Thread(target=self._interpret_message, args=(action, args, connection))
                    worker.start()

                    if action == 'quit':
                        worker.join()
                        self._quit()
            else:
                # Handle uncontrolled connection loss
                self.send_queues.pop(connection)
                self.sel.unregister(connection)
                self.logger.debug("Connection to client on %s was lost!" % connection.getpeername()[1])
                connection.close()
        except socket.error as e:
            self.logger.error("Something went wrong while receiving a message. Check debug for more information")
            self.logger.debug("Socket excpetion: %s" % e)
            self.send_queues.pop(connection)
            self.sel.unregister(connection)
            connection.close()

    def _interpret_message(self, action, args, connection):
        self.logger.debug("Action: %s, args: %s" % (action, args))
        func = self.function_mapping.get(action)

        if action == 'unsubscribe':
            self.send_queues.pop(connection)
            self.sel.unregister(connection)
            self.logger.debug("Client %s unsubscribed" % connection.getpeername()[0])
            connection.close()
            return

        response_type = self.receiver_mapping.get(action)
        if response_type:
            try:
                ret = func(*args)
            except TypeError:
                self.logger.error("Ignoring unrecognized action '%s'" % action)
                return
            action = '%s_response' % action
            message = actionSerializer.serialize_request(action, [ret])
            if response_type == 'all':
                for key in self.send_queues:
                    message_queue = self.send_queues.get(key)
                    message_queue.put(message)
            elif response_type == 'single':
                self.send_queues[connection].put(message)

        else:
            try:
                func(*args)
            except TypeError:
                self.logger.error("Ignoring unrecognized action '%s'" % action)
                return

    def _process_events(self):
        """Process events enqueued by the manager and send them to connected clients if necessary.

        :return: None
        """
        # Put events received by slave manager into event queue to forward to clients
        while not self.cc.slave_server.notify_queue.empty():
            event = self.cc.slave_server.notify_queue.get_nowait()
            self.event_queue.put(event)

        while not self.event_queue.empty():
            event = self.event_queue.get_nowait()
            message = actionSerializer.serialize_request('queue_event', [event])
            for key in self.send_queues:
                message_queue = self.send_queues.get(key)
                message_queue.put(message)

            if isinstance(event, events.DisconnectEvent):
                self.cc.host_states[event.host_name] = config.HostState.DISCONNECTED

    def _start_component_wrapper(self, comp_id, force_mode=False):
        try:
            comp = self.cc.get_component_by_id(comp_id)
            self.cc.start_component(comp, force_mode)
        except exceptions.ComponentNotFoundException as e:
            self.logger.error(e.message)

    def _check_component_wrapper(self, comp_id):
        try:
            comp = self.cc.get_component_by_id(comp_id)
            self.cc.check_component(comp)
        except exceptions.ComponentNotFoundException as e:
            self.logger.error(e.message)

    def _stop_component_wrapper(self, comp_id):
        try:
            comp = self.cc.get_component_by_id(comp_id)
            self.cc.stop_component(comp)
        except exceptions.ComponentNotFoundException as e:
            self.logger.error(e.message)

    def _handle_start_clone_session(self, comp_id):
        comp = self.cc.get_component_by_id(comp_id)

        if self.cc.run_on_localhost(comp):
            self.cc.start_local_clone_session(comp)
        else:
            self.cc.start_remote_clone_session(comp)

    def _send_config(self):
        return self.cc.config

    def _send_host_list(self):
        return self.cc.host_states

    def _send_host_stats(self):
        return self.cc.host_stats

    def _handle_sigint(self, signum, frame):
        self.logger.debug("Received C-c")
        self._quit()
        worker = threading.Thread(target=self.cc.cleanup, args=[True])
        worker.start()
        worker.join()

    def _quit(self):
        self.logger.debug("Stopping Server...")
        self.send_queues = {}
        self.keep_running = False


class SlaveManagementServer(BaseServer):
    def __init__(self):
        """Init slave managing socket server."""
        BaseServer.__init__(self)
        self.notify_queue = queue.Queue()
        self.function_mapping = {
            'queue_event': self._forward_event,
            'auth': None,
            'unsubscribe': None
        }
        self.check_buffer = {}
        self.slave_log_handlers = {}
        self.port_mapping = {}

        server_address = ('localhost', 0)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setblocking(False)
        try:
            server.bind(server_address)
            self.logger.info("Starting slave management server on localhost:%s" % server.getsockname()[1])
            self.port = server.getsockname()[1]
        except socket.error as e:
            if e.errno == 98:
                self.logger.critical("Server adress is already in use! This is odd, free port should be chosen "
                                     "automatically by socket module...")
                self.keep_running = False
            else:
                self.logger.critical("Error while trying to bind server adress: %s" % e)
                self.keep_running = False
        server.listen(5)
        self.sel.register(server, selectors.EVENT_READ, self.accept)

        self.thread = threading.Thread(target=self._run_loop)

    def start(self):
        self.thread.start()

    def kill_slaves(self, full):
        """Send shutdown command to all connected slave client sockets.

        :param full: Whether the tmux session is killed too
        :type full: bool
        :return: None
        """
        if full:
            action = 'quit'
        else:
            action = 'suspend'
        payload = []
        message = actionSerializer.serialize_request(action, payload)

        for host in self.send_queues:
            slave_queue = self.send_queues.get(host)
            slave_queue.put(message)

    def stop(self):
        self._quit()
        if self.thread.is_alive():
            self.thread.join()
        self.logger.info("Slave server successfully shutdown!")

    def _quit(self):
        self.logger.debug("Sending all pending messages to slave clients before quitting server...")
        send_queues = self.send_queues.copy()
        for sub in send_queues:
            while send_queues.get(sub) and not send_queues.get(sub).empty():
                time.sleep(0.5)
        self.logger.debug("... All pending messages sent to slave clients!")
        self.send_queues = {}
        self.keep_running = False

    def _run_loop(self):
        while self.keep_running:
            for key, mask in self.sel.select(timeout=1):
                connection = key.fileobj
                if key.data and self.keep_running:
                    callback = key.data
                    callback(connection, mask)

                else:
                    if mask & selectors.EVENT_READ:
                        self.read(connection)
                    if mask & selectors.EVENT_WRITE:
                        self.write(connection)
            time.sleep(0.3)

        self.sel.close()

    def _forward_event(self, event):
        """Process events enqueued by the manager and send them to connected clients if necessary.

        :return: None
        """
        # self.logger.debug("Forwarding slave client event: %s" % event)
        self.notify_queue.put(event)

        if isinstance(event, events.CheckEvent):
            self.check_buffer[event.comp_id] = event.check_state

    def _interpret_message(self, action, args, connection):
        # self.logger.debug("Action: %s, args: %s" % (action, args))
        func = self.function_mapping.get(action)

        if action == 'unsubscribe':
            self.send_queues.pop(connection)
            self.sel.unregister(connection)
            self.logger.info("Client %s unsubscribed" % connection.getpeername()[0])
            connection.close()
            return

        if action == 'auth':
            hostname = args[0]
            self.port_mapping[connection] = hostname
            return

        try:
            func(*args)
        except TypeError:
            self.logger.error("Ignoring unrecognized slave action '%s'" % action)

    def read(self, connection):
        """Callback for read events"""
        try:
            raw_msglen = connection.recv(4)
            if raw_msglen:
                # A readable client socket has data
                msglen = struct.unpack('>I', raw_msglen)[0]
                data = recvall(connection, msglen)
                action, args = actionSerializer.deserialize(data)

                if action:
                    worker = threading.Thread(target=self._interpret_message, args=(action, args, connection))
                    worker.start()
                else:
                    # Not an action message - trying to decode as log message
                    record = logging.makeLogRecord(args)
                    try:
                        self.slave_log_handlers[connection.getpeername()[0]].handle(record)
                    except KeyError:
                        self.logger.debug("Got log message from yet unhandled slave socket logger")
                        pass
            else:
                # Handle uncontrolled connection loss
                hostname = self.port_mapping.get(connection)

                self.send_queues.pop(connection)
                self.sel.unregister(connection)
                self.logger.error("Connection to client %s was lost!" % hostname)
                self.notify_queue.put(events.SlaveDisconnectEvent(hostname, connection.getpeername()[1]))
                connection.close()
        except socket.error as e:
            self.logger.error("Something went wrong while receiving a message. Check debug for more information")
            self.logger.debug("Socket excpetion: %s" % e)
            self.send_queues.pop(connection)
            self.sel.unregister(connection)
            connection.close()

    def start_slave(self, hostname, config_path, config_name, window, custom_messages=None):
        """Start slave on the remote host.

        :param hostname: Host where the slave is started
        :type hostname: str
        :param config_path: Path to the config file on the remote
        :type config_path: str
        :param window: Tmux window of the host connection
        :type window: libtmux.Window
        :param config_name: Name of the configuration (not the file name!)
        :type config_name: str
        :param custom_messages: Optional custom messages to send on connect (or reconnect).
        :type custom_messages: list of str
        :return: Whether the start was successful or not
        :rtype: bool
        """
        hn = socket.gethostbyname('%s' % hostname)

        if not custom_messages:
            custom_messages = []

        for conn in self.send_queues:
            if hostname == self.port_mapping.get(conn):
                self.logger.debug("Socket to %s already exists! Checking if it is still connected" % hostname)
                try:
                    select.select([conn], [], [conn], 1)
                    self.logger.debug("Connection still up")
                    self._forward_event(events.SlaveReconnectEvent(hostname, conn.getpeername()[1]))

                    for message in custom_messages:
                        self.send_queues.get(conn).put(message)

                    return True
                except socket.error:
                    self.logger.error("Existing connection to %s died. Trying to reconnect...")

        log_file_path = "%s/remote/slave/%s@%s.log" % (config.TMP_LOG_PATH, config_name, hostname)
        slave_log_handler = logging.handlers.RotatingFileHandler(log_file_path)
        hyperion.manager.clear_log(log_file_path, '%s@%s' % (config_name, hostname))

        slave_log_handler.setFormatter(logging.Formatter(config.FORMAT))
        self.slave_log_handlers[hn] = slave_log_handler

        cmd = 'hyperion slave --config %s -H %s -p %s' % (config_path, socket.gethostname(), self.port)
        tmux_cmd = 'tmux new -d -s "%s-slave" "%s"' % (config_name, cmd)
        window.cmd('send-keys', tmux_cmd, 'Enter')

        self.logger.info("Waiting for slave on '%s' (%s) to connect..." % (hn, hostname))
        end_t = time.time() + 4
        while time.time() < end_t:
            for conn in self.send_queues:
                con_host = self.port_mapping.get(conn)
                if con_host:
                    self.logger.debug("'%s' is connected" % con_host)
                if hostname == con_host:
                    self.logger.info("Connection successfully established")

                    for message in custom_messages:
                        self.send_queues.get(conn).put(message)

                    self._forward_event(events.SlaveReconnectEvent(hostname, conn.getpeername()[1]))
                    return True
            time.sleep(.5)

        self.logger.error("Connection to slave failed!")
        return False

    def kill_slave_on_host(self, hostname):
        """Kill a slave session of the current master session running on the remote host.

        :param hostname: Host to kill the slave on
        :type hostname: str
        :return: None
        """
        for conn in self.send_queues:
            if hostname == self.port_mapping.get(conn):
                self.logger.debug("Socket to %s still exists - Sending shutdown" % hostname)
                try:
                    # Test if connection still alive
                    select.select([conn], [], [conn], 1)
                    message = actionSerializer.serialize_request('quit', [])
                    self.send_queues.get(conn).put(message)
                except socket.error:
                    self.logger.error("Existing connection to %s died. Could not send quit command" % hostname)

    def start_clone_session(self, comp_id, hostname):
        action = 'start_clone_session'
        payload = [comp_id]

        connection_queue = None

        message = actionSerializer.serialize_request(action, payload)

        for connection in self.send_queues:
            if self.port_mapping.get(connection) == hostname:
                connection_queue = self.send_queues.get(connection)
                break

        if connection_queue:
            connection_queue.put(message)
        else:
            raise exceptions.SlaveNotReachableException("Slave at %s is not reachable!" % hostname)

    def start_component(self, comp_id, hostname):
        action = 'start'
        payload = [comp_id]

        connection_queue = None

        message = actionSerializer.serialize_request(action, payload)

        for connection in self.send_queues:
            if self.port_mapping.get(connection) == hostname:
                connection_queue = self.send_queues.get(connection)
                break

        if connection_queue:
            connection_queue.put(message)
        else:
            raise exceptions.SlaveNotReachableException("Slave at %s is not reachable!" % hostname)

    def stop_component(self, comp_id, hostname):
        action = 'stop'
        payload = [comp_id]

        connection_queue = None

        message = actionSerializer.serialize_request(action, payload)

        for connection in self.send_queues:
            if self.port_mapping.get(connection) == hostname:
                connection_queue = self.send_queues.get(connection)
                break

        if connection_queue:
            connection_queue.put(message)
        else:
            raise exceptions.SlaveNotReachableException("Slave at %s is not reachable!" % hostname)

    def check_component(self, comp_id, hostname, component_wait):
        self.logger.debug("Sending '%s' check request to %s" % (comp_id, hostname))
        action = 'check'
        payload = [comp_id]

        connection_queue = None

        message = actionSerializer.serialize_request(action, payload)

        for connection in self.send_queues:
            if self.port_mapping.get(connection) == hostname:
                connection_queue = self.send_queues.get(connection)
                break

        self.check_buffer[comp_id] = None

        if connection_queue:
            connection_queue.put(message)
            end_t = time.time() + component_wait + 1

            self.logger.debug("Waiting on '%s' response for %s seconds" % (hostname, component_wait))
            while end_t > time.time():
                if self.check_buffer[comp_id] is not None:
                    break
                time.sleep(.5)
        else:
            self.logger.error("Slave on '%s' is not connected!" % hostname)

        ret = self.check_buffer[comp_id]
        if ret is not None:
            self.logger.debug("Slave answered check request with %s" % config.STATE_DESCRIPTION.get(ret))
            return ret
        else:
            self.logger.error("No answer from slave - returning unreachable")
            return config.CheckState.UNREACHABLE
