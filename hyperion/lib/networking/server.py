import socket
import time
import logging
import sys
import struct
import threading
import hyperion.manager
from signal import *
import hyperion.lib.util.depTree
import hyperion.lib.util.actionSerializer as actionSerializer
import hyperion.lib.util.exception as exceptions

is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as queue
else:
    import queue as queue

try:
    import selectors
except ImportError:
    import selectors2 as selectors


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


class BaseServer:
    """Base class for servers."""
    def __init__(self):
        self.port = None
        self.sel = selectors.DefaultSelector()
        self.keep_running = True
        self.logger = logging.getLogger(__name__)
        self.send_queues = {}
        self.event_queue = queue.Queue()
        signal(SIGINT, self._handle_sigint)

    def accept(self, sock, mask):
        """Callback for new connections"""
        new_connection, addr = sock.accept()
        self.logger.debug('accept({})'.format(addr))
        new_connection.setblocking(False)
        self.send_queues[new_connection] = queue.Queue()
        self.sel.register(new_connection, selectors.EVENT_READ | selectors.EVENT_WRITE)

    def interpret_message(self, action, args, connection):
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
        self.send_queues = {}

        self.keep_running = False


class Server(BaseServer):
    def __init__(self, port, cc):
        BaseServer.__init__(self)
        self.port = port
        self.cc = cc  # type: hyperion.ControlCenter
        self.cc.add_subscriber(self.event_queue)

        server_address = ('', port)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setblocking(False)
        try:
            server.bind(server_address)
            self.logger.debug("Starting server on localhost:%s" % server.getsockname()[1])
        except socket.error as e:
            if e.errno == 98:
                self.logger.critical("Server adress is already in use! Try waiting a few seconds if you are sure there"
                                     " is no other instance running")
                self.keep_running = False
            else:
                self.logger.critical("Error while trying to bind server adress: %s" % e)
                self.keep_running = False
        server.listen(5)

        self.function_mapping = {
            'start_all': self.cc.start_all,
            'start': self._start_component_wrapper,
            'check': self._check_component_wrapper,
            'stop_all': self.cc.stop_all,
            'stop': self._stop_component_wrapper,
            'get_conf': self._send_config,
            'get_host_list': self._send_host_list,
            'quit': self.cc.cleanup,
            'reconnect_with_host': self.cc.reconnect_with_host,
            'unsubscribe': None
        }

        self.receiver_mapping = {
            'get_conf': 'single',
            'get_host_list': 'single'
        }

        self.sel.register(server, selectors.EVENT_READ, self.accept)

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
            self._process_events()
            time.sleep(0.3)

        print('shutting down')
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
                worker = threading.Thread(target=self.interpret_message, args=(action, args, connection))
                worker.start()

                if action == 'quit':
                    worker.join()
                    self._quit()
            else:
                # Handle uncontrolled connection loss
                self.send_queues.pop(connection)
                self.sel.unregister(connection)
                self.logger.debug("Connection to client %s was lost!" % connection.getpeername()[0])
                connection.close()
        except socket.error as e:
            self.logger.error("Something went wrong while receiving a message. Check debug for more information")
            self.logger.debug("Socket excpetion: %s" % e)
            self.send_queues.pop(connection)
            self.sel.unregister(connection)
            connection.close()

    def interpret_message(self, action, args, connection):
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
        while not self.event_queue.empty():
            event = self.event_queue.get_nowait()
            self.logger.debug("Forwarding event: %s" % event)
            message = actionSerializer.serialize_request('queue_event', [event])
            for key in self.send_queues:
                message_queue = self.send_queues.get(key)
                message_queue.put(message)

    def _start_component_wrapper(self, comp_id):
        try:
            comp = self.cc.get_component_by_id(comp_id)
            self.cc.start_component(comp)
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

    def _send_config(self):
        return self.cc.config

    def _send_host_list(self):
        lst = {}
        for key, val in self.cc.host_list.items():
            if val:
                lst[key] = True
            else:
                lst[key] = False
        return lst
