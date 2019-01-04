import config


class BaseEvent(object):
    """Abstract base class for all events."""
    def __init__(self):
        pass


class ComponentEvent(BaseEvent):
    """Abstract parent class for all kinds of events dispatched by the core."""
    def __init__(self, comp_id):
        """Create event for component with id 'comp_id'.

        :param comp_id: Id of the component the event belongs to.
        :type comp_id: str
        """
        BaseEvent.__init__(self)
        self.comp_id = comp_id


class CheckEvent(ComponentEvent):
    """Inform about the result of a run check for a component."""
    def __init__(self, comp_id, check_state):
        """Create check event for component with id 'comp_id' and result 'check_state'.

        :param comp_id: Id of the component the event belongs to
        :type comp_id: str
        :param check_state: Result of the component check
        :type check_state: config.CheckState
        """
        ComponentEvent.__init__(self, comp_id)
        self.check_state = check_state

    def __str__(self):
        return str("CheckEvent - %s: %s" % (self.comp_id, config.STATE_DESCRIPTION.get(config.CheckState(
            self.check_state
        ))))


class StartingEvent(ComponentEvent):
    """Signal that a start of a certain component will be attempted."""
    def __init__(self, comp_id):
        """Create starting event for component with id 'comp_id'.

        :param comp_id: Id of the component the event belongs to.
        :type comp_id: str
        """
        ComponentEvent.__init__(self, comp_id)

    def __str__(self):
        return str("StartingEvent - %s" % self.comp_id)


class StoppingEvent(ComponentEvent):
    """Signal that a stop of a certain component will be attempted."""
    def __init__(self, comp_id):
        """Create stopping event for component with id 'comp_id'.

        :param comp_id: Id of the component the event belongs to.
        :type comp_id: str
        """
        ComponentEvent.__init__(self, comp_id)

    def __str__(self):
        return str("StoppingEvent - %s" % self.comp_id)


class CrashEvent(ComponentEvent):
    """Signal that a component crashed."""
    def __init__(self, comp_id, remote=False):
        """Create crash event for component with id 'comp_id'.

        :param comp_id: Id of the component the event belongs to.
        :type comp_id: str
        :param remote: Whether the component is run on a remote host or not (default: False)
        :type remote: bool
        """
        ComponentEvent.__init__(self, comp_id)
        self.host = comp_id.split('@')[1]
        self.is_remote = remote
        self.message = "Component '%s' crashed" % comp_id

    def __str__(self):
        return str("CrashEvent - %s" % self.comp_id)


class DisconnectEvent(BaseEvent):
    """Signal that connection to host 'host_name' was lost."""
    def __init__(self, host_name):
        """Create disconnect event for host 'host_name'

        :param host_name: Name of the host the connection to was lost
        :type host_name: str
        """
        BaseEvent.__init__(self)
        self.host_name = host_name
        self.message = 'Lost connection to remote host %s' % host_name

    def __str__(self):
        return str("DisconnectEvent - %s" % self.host_name)


class SlaveDisconnectEvent(DisconnectEvent):
    """Signal that the socket connection to a slave has died."""
    def __init__(self, host_name, port):
        """Create a socket disconnect event for host `hostname`.

        :param host_name: Name of the host the slave was running on
        :type host_name: str
        :param port: Port the slave was running on
        """
        super(SlaveDisconnectEvent, self).__init__(host_name)
        self.host_name = host_name
        self.port = port
        self.message = 'Lost connection to slave on %s:%s' % (host_name, port)

    def __str__(self):
        return str("SlaveDisconnectEvent - %s:%s" % (self.host_name, self.port))


class ReconnectEvent(BaseEvent):
    """Signal reconnection to host 'host_name'."""
    def __init__(self, host_name):
        """Create reconnect event for host 'host_name'.

        :param host_name: Name of the remote host
        :type host_name: str
        """
        BaseEvent.__init__(self)
        self.host_name = host_name
        self.message = 'Lost connection to remote host %s' % host_name

    def __str__(self):
        return str("ReconnectEvent - %s" % self.host_name)


class SlaveReconnectEvent(ReconnectEvent):
    """Signal reconnection to slave on host `host`."""
    def __init__(self, host_name, port):
        """Create slave reconnect event for `host` on `port`.

        :param host_name: Host that reconnected
        :type host_name: str
        :param port: Remote
        :type port: int
        """
        super(SlaveReconnectEvent, self).__init__(host_name)
        self.host_name = host_name
        self.port = port
        self.message = "Reconnected to '%s' on '%s'" % (host_name, port)

    def __str__(self):
        return str("SlaveReconnectEvent - %s:%s" % (self.host_name, self.port))


class StartReportEvent(BaseEvent):
    """Inform about the result of a component start."""
    def __init__(self, component, failed_comps):
        """Create start report event.

        :param component: Component that will be started (or 'all' if start all was selected)
        :type component: str
        :param failed_comps: Failed component with their status
        :type failed_comps: dict
        """
        super(StartReportEvent, self).__init__()
        self.component = component
        self.failed_comps = failed_comps

    def __str__(self):
        return str("StartReportEvent - %s" % self.component)


class ServerDisconnectEvent(BaseEvent):
    """Inform the ui about a server connection loss."""
    def __init__(self):
        super(ServerDisconnectEvent, self).__init__()


class ConfigReloadEvent(BaseEvent):
    """Inform about config reload"""
    def __init__(self, config, host_states):
        super(ConfigReloadEvent, self).__init__()
        self.config = config
        self.host_states = host_states
