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
from hyperion.manager import AbstractController, setup_ssh_config, SlaveManager
import hyperion.lib.util.events as events
from signal import *
from subprocess import Popen, PIPE

from typing import Any, Union, Callable, Optional

import selectors
import queue

from hyperion.lib.util.types import Component, Config


def recvall(connection: socket.socket, n: int) -> bytes:
    """Helper function to recv n bytes.

    To read a message with an expected size and combine it to one object, even if it was split into more than one
    packet.

    Parameters
    ----------
    connection : socket.socket
        Socket to read from.
    n : int
        Size of the message to read in bytes.

    Returns
    -------
    str
        Expected message combined into one string.
    """

    data = b""
    while len(data) < n:
        packet = connection.recv(n - len(data))
        if not packet:
            return b''
        data += packet
    return data


class BaseClient(object):
    """Base class for socket clients."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.logger = logging.getLogger(self.__class__.__name__)
        self.send_queue = queue.Queue() # type: queue.Queue
        self.mysel = selectors.DefaultSelector()
        self.keep_running = True

        signal(SIGINT, self._handle_sigint)

    def _handle_sigint(self, signum: int, frame: Any) -> None:
        self.logger.debug("Received C-c")
        self._quit()

    def _quit(self) -> None:
        """Signal client to stop."""
        self.keep_running = False

    def _interpret_message(self, action: str, args: list[Any]) -> None:
        """Resolve action from string and run appropriate function with `args`.

        Parameters
        ----------
        action : str
            Encoded action type to by run.
        args : list[Any]
            Arguments to supply to resolved action.

        Raises
        ------
        NotImplementedError
            If the abstract function is not overridden in the subclass.
        """
        raise NotImplementedError

    def _loop(self) -> None:
        raise NotImplementedError

    def is_localhost(self, hostname: str) -> bool:
        """Check if `hostname` resolves to localhost.

        Parameters
        ----------
        hostname : str
            Name of host to check.

        Returns
        -------
        bool
            True if `host` resolves to localhost.

        Raises
        ------
        exceptions.HostUnknownException
            If the host is not known to the system.
        """

        if hostname == "localhost":
            hostname = self.host

        try:
            hn_out = socket.gethostbyname(f"{hostname}")
            if hn_out == "127.0.0.1" or hn_out == "127.0.1.1" or hn_out == "::1":
                self.logger.debug(f"Host '{hostname}' is localhost")
                return True
            else:
                self.logger.debug(f"Host '{hostname}' is not localhost")
                return False
        except socket.gaierror as err:
            self.logger.debug(f"{hostname} gaierror: {err}")
            raise exceptions.HostUnknownException(
                f"Host '{hostname}' is unknown! Update your /etc/hosts file!"
            )

    def run_on_localhost(self, comp: Component) -> bool:
        """Check if component `comp` is run on localhost or not.

        Parameters
        ----------
        comp : dict
            Config of component to check.

        Returns
        -------
        bool
            True if component is run on localhost or not.

        Raises
        ------
        exceptions.HostUnknownException
            If host is not known by the system.
        """

        try:
            return self.is_localhost(comp["host"])
        except exceptions.HostUnknownException as ex:
            raise ex

    def forward_over_ssh(self) -> Union[int, bool]:
        """Forwards a random local free port to the remote host port via a ssh connection.

        Determines a free port by binding with socket, the socket is then closed and the used port is passed to a
        background ssh port forward command, that will fail if the forwarding did not succeed. The ssh forward command
        is based on the approach in https://gist.github.com/scy/6781836:


        `The magic here is -f combined with sleep 10, which basically says "wait until the connection is there and the
        ports are open before you go into the background, but close yourself after 10 seconds". And here comes the fun
        part: SSH won't terminate as long as forwarded ports are still in use. So what it really means is that
        subsequent scripts have 10 seconds to open the port and then can keep it open as long as they want to.`


        Use inside a while loop checking the output value to ensure the forward worked!

        Returns
        -------
        Union[int, bool]
            The local port that is forwarded or False, if it did not succeed.
        """

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", 0))
        addr = s.getsockname()
        local_port = addr[1]
        s.close()

        # Forward port over SSH
        cmd = (
            "ssh -f -F %s -L %s:localhost:%s -o ExitOnForwardFailure=yes %s sleep 10"
            % (config.CUSTOM_SSH_CONFIG_PATH, local_port, self.port, self.host)
        )
        tunnel_process = Popen(
            f"{cmd}", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE
        )

        while tunnel_process.poll() is None:
            time.sleep(0.5)

        if tunnel_process.returncode == 0:
            self.logger.debug(
                f"Port forwarding succeeded - {self.port}:localhost:{local_port} {self.host}"
            )
            return local_port
        else:
            self.logger.debug("SSH Forwarding failed")
            return False


class RemoteSlaveInterface(BaseClient):
    def __init__(
        self, host: str, port: int, cc: SlaveManager, loop_in_thread: bool = False
    ) -> None:
        """Init remote slave interface for communication to the server at `host` on `port` with slave controller `cc`.

        Parameters
        ----------
        host : str
            Hostname of the server to connect to.
        port : int
            Port of the server to connect to.
        cc : SlaveManager
            Slave manager to dispatch calls to and forward messages from.
        loop_in_thread : bool, optional
            Whether to run the loop function in an extra thread. Useful for unit tests, by default False
        """

        BaseClient.__init__(self, host, port)
        self.cc = cc

        server_address = (host, port)
        self.sock = sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.event_queue = queue.Queue() # type: queue.Queue
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
                        self.logger.critical(
                            "SSH connection to server can not be established - Quitting. "
                            "Are ssh keys set up?"
                        )
                        self._quit()
                        sys.exit(config.ExitStatus.SSH_FAILED.value)
                    tries += 1
                    time.sleep(0.5)
                server_address = ("", local_port)
        except exceptions.HostUnknownException:
            self.logger.critical(f"Cannot connect to server: host '{host}' unknown!")
            self._quit()
            sys.exit(config.ExitStatus.NO_MASTER_RUNNING.value)

        try:
            self.logger.debug("connecting to {} port {}".format(*server_address))
            sock.connect(server_address)
        except socket.error:
            self.logger.critical(
                "Master session does not seem to be running. Quitting remote client"
            )
            self._quit()
            sys.exit(config.ExitStatus.NO_MASTER_RUNNING.value)
        sock.setblocking(False)

        # Set up the selector to watch for when the socket is ready
        # to send data as well as when there is data to read.
        self.mysel.register(
            sock,
            selectors.EVENT_READ | selectors.EVENT_WRITE,
        )

        self.function_mapping: dict[str, Callable] = {
            "start": self._start_wrapper,
            "check": self._check_wrapper,
            "stop": self._stop_wrapper,
            "quit": self._quit,
            "suspend": self._suspend,
            "conf_reload": self.cc.reload_config,
            "start_clone_session": self._start_clone_session_wrapper,
            "stat_monitoring": self._start_monitoring,
        }
        self._send_auth()

        if not loop_in_thread:
            self._loop()
        else:
            self.worker = worker = threading.Thread(target=self._loop)
            worker.start()

        self.logger.debug("Shutdown complete!")

    def _send_auth(self) -> None:
        action = "auth"
        payload = [socket.gethostname()]
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def _suspend(self) -> None:
        self.keep_running = False
        worker = threading.Thread(
            target=self.cc.cleanup, args=[False], name="Suspend slave thread"
        )
        worker.start()
        worker.join()

    def _quit(self) -> None:
        self.keep_running = False
        worker = threading.Thread(
            target=self.cc.cleanup, args=[True], name="Shutdown slave thread"
        )
        worker.start()
        worker.join()

    def _interpret_message(self, action: str, args: list[object]) -> None:
        self.logger.debug(f"Action: {action}, args: {args}")
        func = self.function_mapping.get(action)
        if func is not None:
            try:
                func(*args)
                return
            except TypeError:
                pass
        self.logger.error(f"Ignoring unrecognized slave action '{action}'")

    def _start_clone_session_wrapper(self, comp_id: str) -> None:
        self.cc.start_local_clone_session(self.cc.get_component_by_id(comp_id))

    def _start_wrapper(self, comp_id: str) -> None:
        self.cc.start_component(self.cc.get_component_by_id(comp_id))

    def _check_wrapper(self, comp_id: str) -> None:
        self.cc.check_component(self.cc.get_component_by_id(comp_id))

    def _stop_wrapper(self, comp_id: str) -> None:
        self.cc.stop_component(self.cc.get_component_by_id(comp_id))

    def _process_events(self) -> None:
        """Process events enqueued by the manager and send them to connected clients if necessary."""

        while not self.event_queue.empty():
            event = self.event_queue.get_nowait()
            # self.logger.debug("Forwarding event '%s' to slave manager server" % event)
            message = actionSerializer.serialize_request("queue_event", [event])
            self.send_queue.put(message)

    def _loop(self) -> None:
        self.logger.debug("Started slave client messaging loop")
        # Keep alive until shutdown is requested and no messages are left to send
        while self.keep_running:
            for key, mask in self.mysel.select(timeout=1):
                connection: socket.socket = key.fileobj # type: ignore[assignment]

                if mask & selectors.EVENT_READ:
                    try:
                        raw_msglen = connection.recv(4)
                    except:
                        self.logger.critical("Exception")
                    if raw_msglen:
                        # A readable client socket has data
                        msglen = struct.unpack(">I", raw_msglen)[0]
                        data = recvall(connection, msglen)
                        action, args = actionSerializer.deserialize(data)
                        if action is not None:
                            assert isinstance(args, list)
                            self._interpret_message(action, args)
                        else:
                            self.logger.warn(f"Could not retrieve known action from {data.decode('utf-8')}! Ignoring message")

                    # Interpret empty result as closed connection
                    else:
                        self.keep_running = False
                        # Reset queue for shutdown condition
                        self.send_queue = queue.Queue()
                        self.logger.critical("Connection to server was lost!")
                        self._quit()

                if mask & selectors.EVENT_WRITE:
                    if (
                        not self.send_queue.empty()
                    ):  # Server is ready to read, check if we have messages to send
                        self.logger.debug("Sending next message in queue to Server")
                        next_msg = self.send_queue.get()
                        self.sock.sendall(next_msg)
            self._process_events()
            time.sleep(0.5)
        self.logger.debug("Exiting messaging loop")

    def _start_monitoring(self, rate: float) -> None:
        self.logger.debug(f"Starting stat monitor with rate {rate}")
        config.LOCAL_STAT_MONITOR_RATE = rate
        self.cc.stat_thread.start()
        self.cc.stat_thread.add_subscriber(self.event_queue)


class RemoteControllerInterface(AbstractController, BaseClient):
    """Controller instance meant to act as an interface to the main server. This should be used by UIs."""    
    def _stop_remote_component(self, comp: Component) -> None:
        self.logger.critical("This function should not be called in this context!")
        raise NotImplementedError

    def _start_remote_component(self, comp: Component) -> None:
        self.logger.critical("This function should not be called in this context!")
        raise NotImplementedError

    def _check_remote_component(self, comp: Component) -> config.CheckState:
        self.logger.critical("This function should not be called in this context!")
        raise NotImplementedError

    def reload_config(self) -> None:
        action = "reload_config"
        payload: list[Any] = []
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def __init__(self, host: str, port: int) -> None:
        AbstractController.__init__(self, None)
        BaseClient.__init__(self, host, port)

        self.host_list: list[str] = []
        self.host_states: dict[str, config.HostConnectionState] = {}
        self.config: Config = {}
        self.host_stats: dict[str, list[str]] = {}
        self.mounted_hosts: list[str] = []

        self.function_mapping: dict[str, Callable] = {
            "get_conf_response": self._set_config,
            "get_host_list_response": self._set_host_list,
            "get_host_stats_response": self._set_host_stats,
            "queue_event": self._forward_event,
        }

        server_address = (host, port)
        self.logger.debug("connecting to {} port {}".format(*server_address))
        self.sock = sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if not self.is_localhost(host):
            if not setup_ssh_config():
                self._quit()

            local_port = None
            while not local_port:
                local_port = self.forward_over_ssh()
            server_address = ("", local_port)

        try:
            sock.connect(server_address)
        except socket.error:
            self.logger.critical(
                "Master session does not seem to be running. Quitting remote client"
            )
            self.cleanup()
            sys.exit(config.ExitStatus.NO_MASTER_RUNNING.value)
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

        self.session_name = self.config["name"]

        for host in self.host_list:
            if not self.is_localhost(host):
                self._mount_host(host)

    def start_remote_clone_session(self, comp: Component) -> None:
        action = "start_clone_session"
        payload: list[Any] = [comp["id"]]
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def request_config(self) -> None:
        action = "get_conf"
        payload: list[Any] = []
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

        action = "get_host_list"
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

        action = "get_host_stats"
        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def _quit(self) -> None:
        self.keep_running = False
        self.cleanup(False)

    def cleanup(
        self, full: bool = False, exit_code: config.ExitStatus = config.ExitStatus.FINE
    ) -> None:
        if full:
            action = "quit"
            message = actionSerializer.serialize_request(action, [full])
            self.logger.debug("Sending quit to server")
        else:
            action = "unsubscribe"
            message = actionSerializer.serialize_request(action, [])
            self.logger.debug("Sending unsubscribe to server")
        self.send_queue.put(message)

        for host in self.mounted_hosts:
            self.logger.debug("Unmounting host %s" % host)
            self._unmount_host(host)

        self.keep_running = False

    def get_component_by_id(self, comp_id: str) -> Component:
        for group in self.config["groups"]:
            for comp in group["components"]:
                if comp["id"] == comp_id:
                    self.logger.debug("Component '%s' found" % comp_id)
                    return comp
        raise exceptions.ComponentNotFoundException(comp_id)

    def kill_session_by_name(self, session_name: str) -> None:
        self.logger.debug("Serializing kill session by name")
        action = "kill_session"
        payload = [session_name]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def start_all(self, force_mode: bool = False) -> None:
        action = "start_all"
        message = actionSerializer.serialize_request(action, [force_mode])
        self.send_queue.put(message)

    def start_component(self, comp: Component, force_mode: bool = False) -> config.StartState:
        self.logger.debug("Serializing component start")
        action = "start"
        payload: list[Any] = [comp["id"], force_mode]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)
        return config.StartState.STARTED # meaningless return to satisfy linter

    def stop_all(self) -> None:
        action = "stop_all"
        message = actionSerializer.serialize_request(action, [])
        self.send_queue.put(message)

    def stop_component(self, comp: Component) -> None:
        self.logger.debug("Serializing component stop")
        action = "stop"
        payload: list[Any] = [comp["id"]]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

    def check_component(self, comp: Component, broadcast: bool = False) -> config.CheckState:
        """Sends component check request to the server.

        Parameters
        ----------
        comp : Component
            Component to check.
        broadcast : bool, optional
            Whether the result should be broadcast, by default False

        Returns
        -------
        config.CheckState
            The result comes asyncronously from the server, so a meaningless constant is returned to satisfy linters.
        """        
        self.logger.debug("Serializing component check")
        action = "check"
        payload: list[Any] = [comp["id"]]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)

        # to satisfy linter
        return config.CheckState.UNKNOWN

    def _interpret_message(self, action: str, args: list[Any]) -> None:
        func = self.function_mapping.get(action)
        if func is not None:
            try:
                func(*args)
                return
            except TypeError:
                pass
        self.logger.error(f"Ignoring unrecognized slave action '{action}'")

    def _set_config(self, config: Config) -> None:
        self.config = config
        self.logger.debug("Got config from server")

    def _set_host_list(self, host_list: list[str]) -> None:
        self.host_list = host_list
        self.logger.debug("Updated host list")

    def _set_host_stats(self, host_stats: dict[str, list[str]]) -> None:
        self.host_stats = host_stats
        self.logger.debug("Set host stats")
        self.logger.debug(host_stats)

    def _forward_event(self, event: events.BaseEvent) -> None:
        if self.monitor_queue:
            self.monitor_queue.put(event)

        # Special events handling
        if isinstance(event, events.SlaveReconnectEvent):
            self.host_states[event.host_name] = config.HostConnectionState.CONNECTED
        elif isinstance(event, events.SlaveDisconnectEvent):
            self.host_states[event.host_name] = config.HostConnectionState.SSH_ONLY
        elif isinstance(event, events.DisconnectEvent):
            self.host_states[event.host_name] = config.HostConnectionState.DISCONNECTED
            self._unmount_host(event.host_name)
        elif isinstance(event, events.ReconnectEvent):
            self.host_states[event.host_name] = config.HostConnectionState.SSH_ONLY
            self._mount_host(event.host_name)
        elif isinstance(event, events.ConfigReloadEvent):
            self.logger.debug("Updating config and host list")
            self.config = event.config
            self.host_states = event.host_states
        elif isinstance(event, events.StatResponseEvent):
            self.host_stats[event.hostname] = [
                f"{event.load:.2f}",
                f"{event.cpu:.2f}%%",
                f"{event.mem:.2f}%%",
            ]

    def _loop(self) -> None:
        # Keep alive until shutdown is requested and no messages are left to send
        while self.keep_running or not self.send_queue.empty():
            for key, mask in self.mysel.select(timeout=1):
                connection: socket.socket = key.fileobj # type: ignore[assignment]

                if mask & selectors.EVENT_READ:
                    raw_msglen = connection.recv(4)
                    if raw_msglen:
                        # A readable client socket has data
                        msglen = struct.unpack(">I", raw_msglen)[0]
                        data = recvall(connection, msglen)
                        action, args = actionSerializer.deserialize(data)
                        if action is not None:
                            assert isinstance(args, list)
                            self._interpret_message(action, args)
                        else:
                            self.logger.warn(f"Could not retrieve known action from {data.decode('utf-8')}! Ignoring message")

                    # Interpret empty result as closed connection
                    else:
                        self.keep_running = False
                        # Reset queue for shutdown condition
                        self.send_queue = queue.Queue()
                        self.logger.critical("Connection to server was lost!")
                        self.monitor_queue.put(events.ServerDisconnectEvent())

                if mask & selectors.EVENT_WRITE:
                    if (
                        not self.send_queue.empty()
                    ):  # Server is ready to read, check if we have messages to send
                        self.logger.debug("Sending next message in queue to Server")
                        next_msg = self.send_queue.get()
                        self.sock.sendall(next_msg)
            time.sleep(0.4)

    def add_subscriber(self, subscriber_queue: queue.Queue) -> None:
        """Set reference to ui event queue.

        Parameters
        ----------
        subscriber_queue : queue.Queue
            Event queue of the used UI.
        """
        self.monitor_queue = subscriber_queue

    ###################
    # Host related
    ###################
    def _mount_host(self, hostname: str) -> None:
        """Mount remote host log directory via sshfs.

        Parameters
        ----------
        hostname : str
            Remote host name.
        """

        directory = f"{config.TMP_LOG_PATH}/{hostname}"
        # First unmount to prevent unknown permissions issue on disconnected mountpoint
        self._unmount_host(hostname)

        state = self.host_states[hostname]
        if not state or state == config.HostConnectionState.DISCONNECTED:
            self.logger.error(
                f"'{hostname}' seems not to be connected. Aborting mount! Logs will not be available"
            )
            return
        try:
            os.makedirs(directory)
        except OSError as err:
            if err.errno == 17:
                # Dir already exists
                pass
            else:
                self.logger.error(
                    f"Error while trying to create directory '{directory}'"
                )

        cmd = "sshfs %s:%s/localhost %s -F %s" % (
            hostname,
            config.TMP_LOG_PATH,
            directory,
            config.SSH_CONFIG_PATH,
        )
        self.logger.debug(f"running command: {cmd}")
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)

        while p.poll() is None:
            time.sleep(0.5)

        if p.returncode == 0:
            self.logger.debug(f"Successfully mounted remote '{hostname}' with sshfs")
            self.mounted_hosts.append(hostname)
        else:
            self.logger.error(
                f"Could not mount remote '{hostname}' with sshfs - remote logs will not be accessible!"
            )
            if p.stderr is not None:
                err_out_list_raw = p.stderr.readlines()
                if len(err_out_list_raw) > 0:
                    err_out_list = map(lambda x: x.decode(encoding="UTF-8"), err_out_list_raw)
                    self.logger.error(
                        f"sshfs exited with error: {err_out_list} (code: {p.returncode})"
                    )

        self.logger.debug(f"mounted hosts: {self.mounted_hosts}")

    def _unmount_host(self, hostname: str) -> None:
        """Unmount fuse mounted remote log directory.

        Parameters
        ----------
        hostname : str
            Remote host name.
        """

        directory = os.path.join(config.TMP_LOG_PATH, hostname)

        cmd = f"fusermount -u {directory}"
        self.logger.debug(f"running command: {cmd}")
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)

        if hostname in self.mounted_hosts:
            self.mounted_hosts.remove(hostname)

        while p.poll() is None:
            time.sleep(0.5)

        self.logger.debug(f"mounted hosts: {self.mounted_hosts}")

    def reconnect_with_host(self, hostname: str) -> bool:
        """Issues a request to reconnect with the given host to the server.

        Parameters
        ----------
        hostname : str
            Host to connect to.

        Returns
        -------
        bool
            The success is determined asyncronously by the server and sent as event. To satisfy linters, a meaningless static value is returned.
        """        
        action = "reconnect_with_host"
        payload = [hostname]

        message = actionSerializer.serialize_request(action, payload)
        self.send_queue.put(message)
        return False
