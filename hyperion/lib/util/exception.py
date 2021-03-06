
class WindowNotFoundException(Exception):
    """Exception to be thrown when a tmux window could not be found on the server."""
    def __init__(self, message):
        """Create WindowNotFoundException with message ``message``.

        :param message: Message to provide
        :type message: str
        """

        super(Exception, self).__init__(message)


class ComponentNotFoundException(Exception):
    """Exception to be thrown when a searched component is not contained in the current configuration."""
    def __init__(self, component_id):
        """Create exception with detailed message

        :param component_id: Id of the component denoting name and host
        :type component_id: str
        """
        super(Exception, self).__init__("Component with id '%s' could not be found in the current config." %
                                        component_id)


class UnmetDependenciesException(Exception):
    """Exception to be thrown when a dependency in the configuration could not be found."""
    def __init__(self, unmet_list):
        """Create exception with detailed message.

        :param unmet_list: List of unmet requirements
        :type unmet_list: List of str
        """
        super(Exception, self).__init__("At least one component in the configuration has an unmet dependency")
        self.unmet_list = unmet_list


class DuplicateGroupDefinitionException(Exception):
    """Exception to be thrown when a duplicate group definition is found in the sys config"""
    def __init__(self, duplicate_name):
        """Create DuplicateGroupDefinitionException"""
        self.message = "Config is corrupted. Found multiple definitions of component group '%s'" % duplicate_name


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


class SlaveNotReachableException(Exception):
    """Exception to be thrown when a slave is not reachable."""

    def __init__(self, message):
        self.message = message


class MissingComponentDefinitionException(Exception):
    """Exception to be thrown when a file included in a yaml config file could not be found."""

    def __init__(self, filename):
        self.filename = filename
