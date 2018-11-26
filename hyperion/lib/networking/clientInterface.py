import selectors2 as selectors
import socket
import time
import logging
import sys
import struct
import threading
import hyperion.lib.util.actionSerializer as actionSerializer
from hyperion.manager import AbstractController

is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as queue
else:
    import queue as queue


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

# TODO: Add set_dependencies function to instantly return dependency lists to ui calls


class RemoteControllerInterface(AbstractController):
    def __init__(self, host, port):
        super(RemoteControllerInterface, self).__init__(None)
        self.host_list = None
        self.config = None
        self.host = host
        self.port = port
        self.logger = logging.getLogger(__name__)
        self.receive_queue = queue.Queue()
        self.send_queue = queue.Queue()
        self.mysel = selectors.DefaultSelector()
        self.keep_running = True
        self.ui_event_queue = None

        self.function_mapping = {
            'get_conf_response': self._set_config,
            'get_host_list_response': self._set_host_list,
            'check_response': self.register_check_response
        }

        server_address = (host, port)
        self.logger.debug('connecting to {} port {}'.format(*server_address))
        self.sock = sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(server_address)
        except socket.error:
            self.logger.error("Master session does not seem to be running. Quitting remote client")
            self.cleanup()
        sock.setblocking(False)

        # Set up the selector to watch for when the socket is ready
        # to send data as well as when there is data to read.
        self.mysel.register(
            sock,
            selectors.EVENT_READ | selectors.EVENT_WRITE,
        )

        self.thread = threading.Thread(target=self.loop)
        self.thread.start()

        self.request_config()
        while not self.config or not self.host_list:
            self.logger.debug("Waiting for config")
            time.sleep(0.5)

    def request_config(self):
        action = 'get_conf'
        payload = []
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

        action = 'get_host_list'
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def cleanup(self, full=False):
        # TODO: signalize to client endpoint (UI) to shut down.
        sys.exit(1)

    def get_component_by_id(self, comp_name):
        self.logger.debug("Serializing component fetch")

        action = 'get_comp'
        payload = [comp_name]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def get_dep_list(self, comp):
        self.logger.debug("Serializing component dep list")
        action = 'dep_list'
        payload = [comp]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def kill_session_by_name(self, session_name):
        self.logger.debug("Serializing kill session by name")
        action = 'kill_session'
        payload = [session_name]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def start_component_without_deps(self, comp):
        self.logger.debug("Serializing component start")
        action = 'start'
        payload = [comp]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def stop_component(self, comp):
        self.logger.debug("Serializing component stop")
        action = 'stop'
        payload = [comp]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def check_component(self, comp):
        self.logger.debug("Serializing component check")
        action = 'check'
        payload = [comp]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def _interpret_message(self, action, args):
        func = self.function_mapping.get(action)
        func(*args)

    def _set_config(self, config):
        self.config = config
        self.logger.debug("Got config from server")

    def _set_host_list(self, host_list):
        self.host_list = host_list
        self.logger.debug("Updated host list")

    def _provide_check_event(self, CheckState):
        self.logger.debug("NIY")
        # Blocking calls for check? Ui check_component expects non-Null return...
        # TODO: Damn, this means trouble...
        # self.ui_event_queue.put()

    def register_check_response(self, response):
        check_state = response[0]
        comp = response[1]
        self.logger.debug("Check response event registration NIY")
        # TODO: Add check response event to registered queue

    def loop(self):
        while self.keep_running:
            for key, mask in self.mysel.select(timeout=1):
                connection = key.fileobj

                if mask & selectors.EVENT_READ:
                    self.logger.debug("Got read event")
                    raw_msglen = connection.recv(4)
                    if raw_msglen:
                        # A readable client socket has data
                        msglen = struct.unpack('>I', raw_msglen)[0]
                        data = recvall(connection, msglen)
                        self.logger.debug("Received message")
                        action, args = actionSerializer.deserialize(data)
                        self._interpret_message(action, args)

                    # Interpret empty result as closed connection
                    else:
                        self.keep_running = False

                if mask & selectors.EVENT_WRITE:
                    if not self.send_queue.empty():  # Server is ready to read, check if we have messages to send
                        self.logger.debug("Sending next message in queue to Server")
                        next_msg = self.send_queue.get()
                        self.sock.sendall(next_msg)

    def add_subscriber(self, subscriber_queue):
        self.ui_event_queue = subscriber_queue
        # TODO: Generate events out of received messages
