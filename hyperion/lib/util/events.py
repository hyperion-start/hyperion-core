from hyperion.lib.util import config


class BaseEvent(object):
    """Abstract base class for all events."""

    def __init__(self):
        pass


class ComponentEvent(BaseEvent):
    """Abstract parent class for all kinds of events dispatched by the core."""

    def __init__(self, comp_id):
        """Create event for component with id 'comp_id'.

        Parameters
        ----------
        comp_id : str
            Id of the component the event belongs to.
        """

        BaseEvent.__init__(self)
        self.comp_id = comp_id


class StatResponseEvent(BaseEvent):
    """Event to pass the results of stat request."""

    def __init__(self, load, cpu, mem, hostname):
        """Create stat response event with avg load, cpu and memory information.

        Parameters
        ----------
        load : float
            Average load.
        cpu : float
            CPU usage in percent.
        mem : float
            Memory usage in percent.
        hostname : str
            Name of the host these stats are coming from.
        """

        BaseEvent.__init__(self)
        self.load = load
        self.cpu = cpu
        self.mem = mem
        self.hostname = hostname


class CheckEvent(ComponentEvent):
    """Inform about the result of a run check for a component."""

    def __init__(self, comp_id, check_state):
        """Create check event for component with id 'comp_id' and result 'check_state'.

        Parameters
        ----------
        comp_id : str
            Id of the component the event belongs to.
        check_state : config.CheckState
            Result of the component check
        """

        ComponentEvent.__init__(self, comp_id)
        self.check_state = check_state

    def __str__(self):
        return str(
            f"CheckEvent - {self.comp_id}: {config.STATE_DESCRIPTION.get(config.CheckState(self.check_state))}"
        )


class StartingEvent(ComponentEvent):
    """Signal that a start of a certain component will be attempted."""

    def __init__(self, comp_id):
        """Create starting event for component with id 'comp_id'.

        Parameters
        ----------
        comp_id : str
            Id of the component the event belongs to.
        """

        ComponentEvent.__init__(self, comp_id)

    def __str__(self):
        return str(f"StartingEvent - {self.comp_id}")


class StoppingEvent(ComponentEvent):
    """Signal that a stop of a certain component will be attempted."""

    def __init__(self, comp_id):
        """Create stopping event for component with id `comp_id`.

        Parameters
        ----------
        comp_id : str
            Id of the component the event belongs to.
        """

        ComponentEvent.__init__(self, comp_id)

    def __str__(self):
        return str(f"StoppingEvent - {self.comp_id}")


class CrashEvent(ComponentEvent):
    """Signal that a component crashed."""

    def __init__(self, comp_id, remote=False):
        """Create crash event for component with id 'comp_id'.

        Parameters
        ----------
        comp_id : str
            Id of the component the event belongs to.
        remote : bool, optional
            Whether the component is run on a remote host or not, by default False.
        """

        ComponentEvent.__init__(self, comp_id)
        self.host = comp_id.split("@")[1]
        self.is_remote = remote
        self.message = f"Component '{comp_id}' crashed"

    def __str__(self):
        return str(f"CrashEvent - {self.comp_id}")


class DisconnectEvent(BaseEvent):
    """Signal that connection to host 'host_name' was lost."""

    def __init__(self, host_name):
        """Create disconnect event for host `host_name`.

        Parameters
        ----------
        host_name : str
            Name of the host the connection to was lost
        """

        BaseEvent.__init__(self)
        self.host_name = host_name
        self.message = f"Lost connection to remote host {host_name}"

    def __str__(self):
        return str(f"DisconnectEvent - {self.host_name}")


class SlaveDisconnectEvent(DisconnectEvent):
    """Signal that the socket connection to a slave has died."""

    def __init__(self, host_name, port):
        """Create a socket disconnect event for host `hostname`.

        Parameters
        ----------
        host_name : str
            Name of the host the slave was running on
        port : int
            Port the slave was running on
        """

        super(SlaveDisconnectEvent, self).__init__(host_name)
        self.host_name = host_name
        self.port = port
        self.message = f"Lost connection to slave on {host_name}:{port}"

    def __str__(self):
        return str(f"SlaveDisconnectEvent - {self.host_name}:{self.port}")


class ReconnectEvent(BaseEvent):
    """Signal reconnection to host 'host_name'."""

    def __init__(self, host_name):
        """Create reconnect event for host `host_name`.

        Parameters
        ----------
        host_name : str
            Name of the remote host.
        """

        BaseEvent.__init__(self)
        self.host_name = host_name
        self.message = f"Lost connection to remote host {host_name}"

    def __str__(self):
        return str(f"ReconnectEvent - {self.host_name}")


class SlaveReconnectEvent(ReconnectEvent):
    """Signal reconnection to slave on host `host`."""

    def __init__(self, host_name, port):
        """Create slave reconnect event for `host` on `port`.

        Parameters
        ----------
        host_name : str
            Host that reconnected
        port : int
            Remote port
        """

        super(SlaveReconnectEvent, self).__init__(host_name)
        self.host_name = host_name
        self.port = port
        self.message = f"Reconnected to '{host_name}' on '{port}'"

    def __str__(self):
        return str(f"SlaveReconnectEvent - {self.host_name}:{self.port}")


class StartReportEvent(BaseEvent):
    """Inform about the result of a component start."""

    def __init__(self, comp_id, failed_comps):
        """Create start report event for component `comp_id`.

        Parameters
        ----------
        comp_id : str
            Component that will be started (or 'all' if start all was selected)
        failed_comps : dict[str, config.CheckState]
            Failed component with their status
        """

        super(StartReportEvent, self).__init__()
        self.comp_id = comp_id
        self.failed_comps = failed_comps

    def __str__(self):
        return str(f"StartReportEvent - {self.comp_id}")


class ServerDisconnectEvent(BaseEvent):
    """Inform the ui about a server connection loss."""

    def __init__(self):
        super(ServerDisconnectEvent, self).__init__()


class ConfigReloadEvent(BaseEvent):
    """Inform about config reload"""

    def __init__(self, config, host_states):
        """Create ConfigReloadEvent with new config and host information.

        Parameters
        ----------
        config : dict
            New config.
        host_states : dict
            Host status during the reload.
        """

        super(ConfigReloadEvent, self).__init__()
        self.config = config
        self.host_states = host_states
