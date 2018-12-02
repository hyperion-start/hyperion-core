import socket
import time
import logging
import sys
import struct
import hyperion.manager
import hyperion.lib.util.depTree
import hyperion.lib.util.actionSerializer as actionSerializer
import hyperion.lib.util.config as config

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


class Server:
    def __init__(self, port, cc):
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.keep_running = True
        self.cc = cc  # type: hyperion.ControlCenter
        self.logger = logging.getLogger(__name__)
        self.send_queues = {}

        server_address = ('', port)
        self.logger.debug("Starting server on localhost:%s" % port)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setblocking(False)
        server.bind(server_address)
        server.listen(5)

        self.function_mapping = {
            'run': self.cc.start_component_without_deps,
            'check': self._check_handler,
            'stop': self.cc.stop_component,
            'get_conf': self._send_config,
            'get_host_list': self._send_host_list
        }

        self.receiver_mapping = {
            'run': None,
            'check': 'all',
            'stop': None,
            'get_conf': 'single',
            'get_host_list': 'single'
        }

        self.sel.register(server, selectors.EVENT_READ, self.accept)

        while self.keep_running:
            for key, mask in self.sel.select(timeout=1):
                connection = key.fileobj
                if key.data:
                    callback = key.data
                    callback(connection, mask)

                else:
                    if mask & selectors.EVENT_READ:
                        self.read(connection)
                    if mask & selectors.EVENT_WRITE:
                        self.write(connection)
            time.sleep(0.3)

        print('shutting down')
        self.sel.close()

    def write(self, connection):
        """Callback for write events"""
        send_queue = self.send_queues.get(connection)
        if not send_queue.empty():
            # Messages available
            next_msg = send_queue.get()
            connection.sendall(next_msg)
            logging.debug("Sending message to %s" % connection)

    def read(self, connection):
        """Callback for read events"""
        raw_msglen = connection.recv(4)
        if raw_msglen:
            # A readable client socket has data
            msglen = struct.unpack('>I', raw_msglen)[0]
            data = recvall(connection, msglen)
            self.logger.debug("Received message")
            action, args = actionSerializer.deserialize(data)
            self.interpret_message(action, args, connection)
        else:
            # Interpret empty result as closed connection
            print('  closing')
            self.sel.unregister(connection)
            connection.close()
            # Tell the main loop to stop
            self.keep_running = False

    def accept(self, sock, mask):
        "Callback for new connections"
        new_connection, addr = sock.accept()
        print('accept({})'.format(addr))
        new_connection.setblocking(False)
        self.send_queues[new_connection] = queue.Queue()
        self.sel.register(new_connection, selectors.EVENT_READ | selectors.EVENT_WRITE)

    def interpret_message(self, action, args, connection):
        self.logger.debug("Action: %s, args: %s" % (action, args))
        func = self.function_mapping.get(action)
        self.logger.debug("Calling function %s" % func)

        response_type = self.receiver_mapping.get(action)
        if response_type:
            ret = func(*args)
            action = '%s_response' % action
            message = actionSerializer.serialize_request(action, [ret])
            if response_type == 'all':
                for key in self.send_queues:
                    message_queue = self.send_queues.get(key)
                    message_queue.put(message)
            elif response_type == 'single':
                self.send_queues[connection].put(message)

        else:
            func(*args)

    def _check_handler(self, comp):
        check_state = self.cc.check_component(comp)
        return check_state, comp

    def _send_config(self):
        return self.cc.config

    def _send_host_list(self):
        return self.cc.host_list
