from config import CheckState


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


class StartingEvent(ComponentEvent):
    """Signal that a start of a certain component will be attempted."""
    def __init__(self, comp_id):
        """Create starting event for component with id 'comp_id'.

        :param comp_id: Id of the component the event belongs to.
        :type comp_id: str
        """
        ComponentEvent.__init__(self, comp_id)


class StoppingEvent(ComponentEvent):
    """Signal that a stop of a certain component will be attempted."""
    def __init__(self, comp_id):
        """Create stopping event for component with id 'comp_id'.

        :param comp_id: Id of the component the event belongs to.
        :type comp_id: str
        """
        ComponentEvent.__init__(self, comp_id)


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
