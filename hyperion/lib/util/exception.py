
class WindowNotFoundException(Exception):
    """Exception to be thrown when a tmux window could not be found on the server."""
    def __init__(self, message):
        """Create WindowNotFoundException with message ``message``.

        :param message: Message to provide
        :type message: str
        """

        super(Exception, self).__init__(message)


class CircularReferenceException(Exception):
    """Exception to be thrown when a circular dependency is detected in the dependency graph."""
    def __init__(self, node1, node2):
        """Create CircularReferenceException between ``node1`` and ``node2.``

        :param node1: First node involved
        :type node1: Node
        :param node2: Second node involved
        :type node2: Node
        """

        self.node1 = node1
        self.node2 = node2


class EnvNotFoundException(Exception):
    """Exception to be thrown when a custom environment file could not be found."""
    def __init__(self, message):
        """Create EnvNotFoundException.

        :param message: Message to provide
        :type message: str
        """

        self.message = message


class HostUnknownException(Exception):
    """Exception to be thrown when a host can not be resolved."""

    def __init__(self, message):
        self.message = message
