import socket
import time
import logging
import os
import sys
import struct
import threading
import hyperion.lib.util.config as config
import hyperion.lib.util.actionSerializer as actionSerializer
import hyperion.lib.util.exception as exceptions
from hyperion.manager import AbstractController, setup_ssh_config
import hyperion.lib.util.events as events
from signal import *
from subprocess import Popen, PIPE

try:
    import selectors
except ImportError:
    logging.warn("Module selectors not found! Trying to load selectors2")
    try:
        import selectors2 as selectors
    except ImportError as err:
        logging.critical("Neither selectors or selectors2 is installed. You need one of these packages to run hyperion! Err: %s" % err)
        raise err


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


class BaseClient(object):
    """Base class for socket clients."""
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.logger = logging.getLogger(self.__class__.__name__)
        self.send_queue = queue.Queue()
        self.mysel = selectors.DefaultSelector()
        self.keep_running = True

        signal(SIGINT, self._handle_sigint)

    def _handle_sigint(self, signum, frame):
        self.logger.debug("Received C-c")
        self._quit()

    def _quit(self):
        self.keep_running = False

    def _interpret_message(self, action, args):
        raise NotImplementedError

    def _loop(self):
        raise NotImplementedError

    def is_localhost(self, hostname):
        """Check if 'hostname' resolves to localhost.

        :param hostname: Name of host to check
        :type hostname: str
        :return: Whether 'host' resolves to localhost or not
        :rtype: bool
        """
        if hostname == 'localhost':
            hostname = self.host

        try:
            hn_out = socket.gethostbyname('%s' % hostname)
            if hn_out == '127.0.0.1' or hn_out == '127.0.1.1' or hn_out == '::1':
                self.logger.debug("Host '%s' is localhost" % hostname)
                return True
            else:
                self.logger.debug("Host '%s' is not localhost" % hostname)
                return False
        except socket.gaierror as err:
            self.logger.debug("%s gaierror: %s" % (hostname, err))
            raise exceptions.HostUnknownException("Host '%s' is unknown! Update your /etc/hosts file!" % hostname)

    def run_on_localhost(self, comp):
        """Check if component 'comp' is run on localhost or not.

        :param comp: Component to check
        :type comp: dict
        :return: Whether component is run on localhost or not
        :rtype: bool
        """
        try:
            return self.is_localhost(comp['host'])
        except exceptions.HostUnknownException as ex:
            raise ex

    def forward_over_ssh(self):
        """Forwards a random local free port to the remote host port via a ssh connection.

        Determines a free port by binding with socket, the socket is then closed and the used port is passed to a
        background ssh port forward command, that will fail if the forwarding did not succeed. The ssh forward command
        is based on the approach in https://gist.github.com/scy/6781836:


        `The magic here is -f combined with sleep 10, which basically says "wait until the connection is there and the
        ports are open before you go into the background, but close yourself after 10 seconds". And here comes the fun
        part: SSH won't terminate as long as forwarded ports are still in use. So what it really means is that
        subsequent scripts have 10 seconds to open the port and then can keep it open as long as they want to.`


        Use inside a while loop checking the output value to ensure the forward worked!

        :return: The local port that is forwarded or False, if it did not succeed
        :rtype: int or bool
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', 0))
        addr = s.getsockname()
        local_port = addr[1]
        s.close()

        # Forward port over SSH
        cmd = 'ssh -f -F %s -L %s:localhost:%s -o ExitOnForwardFailure=yes %s sleep 10' % (
            config.CUSTOM_SSH_CONFIG_PATH,
            local_port,
            self.port,
            self.host
        )
        tunnel_process = Popen('%s' % cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)

        while tunnel_process.poll() is None:
            time.sleep(.5)

        if tunnel_process.returncode == 0:
            self.logger.debug("Port forwarding succeeded - %s:localhost:%s %s" % (self.port, local_port, self.host))
            return local_port
        else:
            self.logger.debug("SSH Forwarding failed")
            return False


class RemoteSlaveInterface(BaseClient):
    def __init__(self, host, port, cc, loop_in_thread=False):
        """Init remote slave interface for communication to the server at `host` on `port` with slave controller `cc`.

        :param host: Hostname of the server to connect to
        :type host: str
        :param port: Port of the server to connect to
        :type port: int
        :param cc: Slave manager to dispatch calls to and forward messages from
        :type cc: hyperion.manager.SlaveManager
        :param loop_in_thread: Whether to run the loop function in an extra thread. Useful for unit tests and disabled
        by default.
        :type loop_in_thread: bool
        """
        BaseClient.__init__(self, host, port)
        self.cc = cc

        server_address = (host, port)
        self.sock = sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.event_queue = queue.Queue()
        self.cc.add_subscriber(self.event_queue)

        try:
            if not self.is_localhost(host):
                if not setup_ssh_config():
                    self._quit()

                local_port = None
                tries = 0
                while not local_port:
                    local_port = self.forward_over_ssh()
                    if tries == 5:
                        self.logger.critical("SSH connection to server can not be established - Quitting. "
                                             "Are ssh keys set up?")
                        self._quit()
                        sys.exit(config.ExitStatus.SSH_FAILED)
                    tries += 1
                    time.sleep(.5)
                server_address = ('', local_port)
        except exceptions.HostUnknownException:
            self.logger.critical("Cannot connect to server: host '%s' unknown!" % host)
            self._quit()
            sys.exit(config.ExitStatus.NO_MASTER_RUNNING)

        try:
            self.logger.debug('connecting to {} port {}'.format(*server_address))
            sock.connect(server_address)
        except socket.error:
            self.logger.critical("Master session does not seem to be running. Quitting remote client")
            self._quit()
            sys.exit(config.ExitStatus.NO_MASTER_RUNNING)
        sock.setblocking(False)

        # Set up the selector to watch for when the socket is ready
        # to send data as well as when there is data to read.
        self.mysel.register(
            sock,
            selectors.EVENT_READ | selectors.EVENT_WRITE,
        )

        self.function_mapping = {
            'start': self._start_wrapper,
            'check': self._check_wrapper,
            'stop': self._stop_wrapper,
            'quit': self._quit,
            'suspend': self._suspend,
            'conf_reload': self.cc.reload_config,
            'start_clone_session': self._start_clone_session_wrapper
        }
        self._send_auth()

        if not loop_in_thread:
            self._loop()
        else:
            self.worker = worker = threading.Thread(target=self._loop)
            worker.start()
        
        self.logger.debug("Shutdown complete!")

    def _send_auth(self):
        action = 'auth'
        payload = [socket.gethostname()]
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def _suspend(self):
        self.keep_running = False
        worker = threading.Thread(
            target=self.cc.cleanup,
            args=[False],
            name="Suspend slave thread"
        )
        worker.start()
        worker.join()

    def _quit(self):
        self.keep_running = False
        worker = threading.Thread(
            target=self.cc.cleanup,
            args=[True],
            name="Shutdown slave thread"
        )
        worker.start()
        worker.join()

    def _interpret_message(self, action, args):
        self.logger.debug("Action: %s, args: %s" % (action, args))
        func = self.function_mapping.get(action)

        try:
            func(*args)
        except TypeError:
            self.logger.error("Ignoring unrecognized slave action '%s'" % action)

    def _start_clone_session_wrapper(self, comp_id):
        self.cc.start_local_clone_session(self.cc.get_component_by_id(comp_id))

    def _start_wrapper(self, comp_id):
        self.cc.start_component(self.cc.get_component_by_id(comp_id))

    def _check_wrapper(self, comp_id):
        self.cc.check_component(self.cc.get_component_by_id(comp_id))

    def _stop_wrapper(self, comp_id):
        self.cc.stop_component(self.cc.get_component_by_id(comp_id))

    def _process_events(self):
        """Process events enqueued by the manager and send them to connected clients if necessary.

        :return: None
        """
        while not self.event_queue.empty():
            event = self.event_queue.get_nowait()
            self.logger.debug("Forwarding event '%s' to slave manager server" % event)
            message = actionSerializer.serialize_request('queue_event', [event])
            self.send_queue.put(message)

    def _loop(self):
        self.logger.debug("Started slave client messaging loop")
        # Keep alive until shutdown is requested and no messages are left to send
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
                        # Reset queue for shutdown condition
                        self.send_queue = queue.Queue()
                        self.logger.critical("Connection to server was lost!")
                        self._quit()

                if mask & selectors.EVENT_WRITE:
                    if not self.send_queue.empty():  # Server is ready to read, check if we have messages to send
                        self.logger.debug("Sending next message in queue to Server")
                        next_msg = self.send_queue.get()
                        self.sock.sendall(next_msg)
            self._process_events()
            time.sleep(.5)
        self.logger.debug("Exiting messaging loop")


class RemoteControllerInterface(AbstractController, BaseClient):
    def _stop_remote_component(self, comp):
        self.logger.critical("This function should not be called in this context!")
        pass

    def _start_remote_component(self, comp):
        self.logger.critical("This function should not be called in this context!")
        pass

    def _check_remote_component(self, comp):
        self.logger.critical("This function should not be called in this context!")
        pass

    def reload_config(self):
        action = 'reload_config'
        payload = []
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def __init__(self, host, port):
        AbstractController.__init__(self, None)
        BaseClient.__init__(self, host, port)

        self.host_list = None
        self.host_states = None
        self.config = None
        self.host_stats = {}
        self.mounted_hosts = []

        self.function_mapping = {
            'get_conf_response': self._set_config,
            'get_host_list_response': self._set_host_list,
            'get_host_stats_response': self._set_host_stats,
            'queue_event': self._forward_event
        }

        server_address = (host, port)
        self.logger.debug('connecting to {} port {}'.format(*server_address))
        self.sock = sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if not self.is_localhost(host):
            if not setup_ssh_config():
                self._quit()

            local_port = None
            while not local_port:
                local_port = self.forward_over_ssh()
            server_address = ('', local_port)

        try:
            sock.connect(server_address)
        except socket.error:
            self.logger.critical("Master session does not seem to be running. Quitting remote client")
            self.cleanup()
            sys.exit(config.ExitStatus.NO_MASTER_RUNNING)
        sock.setblocking(False)

        # Set up the selector to watch for when the socket is ready
        # to send data as well as when there is data to read.
        self.mysel.register(
            sock,
            selectors.EVENT_READ | selectors.EVENT_WRITE,
        )

        self.thread = threading.Thread(target=self._loop)
        self.thread.start()

        self.request_config()
        while not self.config or not self.host_list:
            self.logger.debug("Waiting for config")
            time.sleep(0.5)

        self.session_name = self.config['name']

        for host in self.host_list:
            if not self.is_localhost(host):
                self._mount_host(host)

    def start_remote_clone_session(self, comp):
        action = 'start_clone_session'
        payload = [comp['id']]
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def request_config(self):
        action = 'get_conf'
        payload = []
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

        action = 'get_host_list'
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def _quit(self):
        self.keep_running = False
        self.cleanup(False)

    def cleanup(self, full=False, exit_code=config.ExitStatus.FINE):
        if full:
            action = 'quit'
            message = actionSerializer.serialize_request(action, [full])
            self.logger.debug("Sending quit to server")
        else:
            action = 'unsubscribe'
            message = actionSerializer.serialize_request(action, [])
            self.logger.debug("Sending unsubscribe to server")
        self.send_queue.put(message)

        for host in self.mounted_hosts:
            self.logger.debug("Unmounting host %s" % host)
            self._unmount_host(host)

        self.keep_running = False

    def get_component_by_id(self, comp_id):
        for group in self.config['groups']:
            for comp in group['components']:
                if comp['id'] == comp_id:
                    self.logger.debug("Component '%s' found" % comp_id)
                    return comp
        raise exceptions.ComponentNotFoundException(comp_id)

    def kill_session_by_name(self, session_name):
        self.logger.debug("Serializing kill session by name")
        action = 'kill_session'
        payload = [session_name]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def start_all(self, force_mode=False):
        action = 'start_all'
        message = actionSerializer.serialize_request(action, [force_mode])
        self.send_queue.put(message)

    def start_component(self, comp, force_mode=False):
        self.logger.debug("Serializing component start")
        action = 'start'
        payload = [comp['id'], force_mode]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def stop_all(self):
        action = 'stop_all'
        message = actionSerializer.serialize_request(action, [])
        self.send_queue.put(message)

    def stop_component(self, comp):
        self.logger.debug("Serializing component stop")
        action = 'stop'
        payload = [comp['id']]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def check_component(self, comp, broadcast=False):
        self.logger.debug("Serializing component check")
        action = 'check'
        payload = [comp['id']]

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
        self.host_states = host_list
        self.logger.debug("Updated host list")

    def _set_host_stats(self, host_stats):
        self.host_stats = host_stats
        self.logger.debug("Set host stats")

    def _forward_event(self, event):
        if self.monitor_queue:
            self.monitor_queue.put(event)

        # Special events handling
        if isinstance(event, events.SlaveReconnectEvent):
            self.host_states[event.host_name] = config.HostState.CONNECTED
        elif isinstance(event, events.SlaveDisconnectEvent):
            self.host_states[event.host_name] = config.HostState.SSH_ONLY
        elif isinstance(event, events.DisconnectEvent):
            self.host_states[event.host_name] = config.HostState.DISCONNECTED
            self._unmount_host(event.host_name)
        elif isinstance(event, events.ReconnectEvent):
            self.host_states[event.host_name] = config.HostState.SSH_ONLY
            self._mount_host(event.host_name)
        elif isinstance(event, events.ConfigReloadEvent):
            self.logger.debug("Updating config and host list")
            self.config = event.config
            self.host_states = event.host_states
        elif isinstance(event, events.StatResponseEvent):
            self.host_stats[event.hostname] = ["%s" % event.load, "%s%%" % event.cpu, "%s%%" % event.mem]

    def _loop(self):
        # Keep alive until shutdown is requested and no messages are left to send
        while self.keep_running or not self.send_queue.empty():
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
                        # Reset queue for shutdown condition
                        self.send_queue = queue.Queue()
                        self.logger.critical("Connection to server was lost!")
                        self.monitor_queue.put(events.ServerDisconnectEvent())

                if mask & selectors.EVENT_WRITE:
                    if not self.send_queue.empty():  # Server is ready to read, check if we have messages to send
                        self.logger.debug("Sending next message in queue to Server")
                        next_msg = self.send_queue.get()
                        self.sock.sendall(next_msg)
            time.sleep(.4)

    def add_subscriber(self, subscriber_queue):
        """Set reference to ui event queue.

        :param subscriber_queue: Event queue of the used ui
        :type subscriber_queue: queue.Queue
        :return: None
        """
        self.monitor_queue = subscriber_queue

    ###################
    # Host related
    ###################
    def _mount_host(self, hostname):
        """Mount remote host log directory via sshfs.

        :param hostname: Remote host name
        :type hostname: str
        :return: None
        """
        directory = "%s/%s" % (config.TMP_LOG_PATH, hostname)
        # First unmount to prevent unknown permissions issue on disconnected mountpoint
        self._unmount_host(hostname)

        state = self.host_states[hostname]
        if not state or state == config.HostState.DISCONNECTED:
            self.logger.error("'%s' seems not to be connected. Aborting mount! Logs will not be available" % hostname)
            return
        try:
            os.makedirs(directory)
        except OSError as err:
            if err.errno == 17:
                # Dir already exists
                pass
            else:
                self.logger.error("Error while trying to create directory '%s'" % directory)

        cmd = 'sshfs %s:%s/localhost %s -F %s' % (hostname,
                                        config.TMP_LOG_PATH,
                                        directory,
                                        config.SSH_CONFIG_PATH
                                        )
        self.logger.debug("running command: %s" % cmd)
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)

        while p.poll() is None:
            time.sleep(.5)

        if p.returncode == 0:
            self.logger.debug("Successfully mounted remote '%s' with sshfs" % hostname)
            self.mounted_hosts.append(hostname)
        else:
            self.logger.error("Could not mount remote '%s' with sshfs - logs will not be accessible!" % hostname)
            self.logger.debug("sshfs exited with error: %s (code: %s)" % (p.stderr.readlines(), p.returncode))

        self.logger.debug("mounted hosts: %s" % self.mounted_hosts)

    def _unmount_host(self, hostname):
        """Unmount fuse mounted remote log directory.

        :param hostname: Remote host name.
        :type hostname: str
        :return: None
        """
        directory = "%s/%s" % (config.TMP_LOG_PATH, hostname)

        cmd = 'fusermount -u %s' % directory
        self.logger.debug("running command: %s" % cmd)
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)

        if hostname in self.mounted_hosts:
            self.mounted_hosts.remove(hostname)

        while p.poll() is None:
            time.sleep(.5)

        self.logger.debug("mounted hosts: %s" % self.mounted_hosts)

    def reconnect_with_host(self, hostname):
        action = 'reconnect_with_host'
        payload = [hostname]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)
