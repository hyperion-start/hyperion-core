from typing import List


class WindowNotFoundException(Exception):
    """Exception to be thrown when a tmux window could not be found on the server."""

    def __init__(self, message: str) -> None:
        """Create WindowNotFoundException with message `message`.

        Parameters
        ----------
        message : str
            Message to provide.
        """

        super(Exception, self).__init__(message)


class ComponentNotFoundException(Exception):
    """Exception to be thrown when a searched component is not contained in the current configuration."""

    def __init__(self, component_id: str) -> None:
        """Create exception with detailed message.

        Parameters
        ----------
        component_id : str
            Id of the component denoting name and host
        """

        self.message = f"Component with id '{component_id}' could not be found in the current config."


class UnmetDependenciesException(Exception):
    """Exception to be thrown when a dependency in the configuration could not be found."""

    def __init__(self, unmet_list: List[str]) -> None:
        """Create exception with detailed message.

        Parameters
        ----------
        unmet_list : List[str]
            List of unmet requirements.
        """

        self.message = "At least one component in the configuration has an unmet dependency"
        self.unmet_list = unmet_list


class DuplicateGroupDefinitionException(Exception):
    """Exception to be thrown when a duplicate group definition is found in the sys config"""

    def __init__(self, duplicate_name: str) -> None:
        """Create DuplicateGroupDefinitionException

        Parameters
        ----------
        duplicate_name : str
            Name of duplicate group.
        """

        self.message = f"Config is corrupted. Found multiple definitions of component group '{duplicate_name}'"


class CircularReferenceException(Exception):
    """Exception to be thrown when a circular dependency is detected in the dependency graph."""

    def __init__(self, node1: str, node2: str) -> None:
        """Create CircularReferenceException between `node1` and `node2`.

        Parameters
        ----------
        node1 : str
            Id of first node involved.
        node2 : str
            Id of second node involved.
        """

        self.node1 = node1
        self.node2 = node2


class EnvNotFoundException(Exception):
    """Exception to be thrown when a custom environment file could not be found."""

    def __init__(self, message: str) -> None:
        """Create EnvNotFoundException.

        Parameters
        ----------
        message : str
            Message to provide.
        """

        self.message = message


class HostUnknownException(Exception):
    """Exception to be thrown when a host can not be resolved."""

    def __init__(self, message: str) -> None:
        """Create a HostUnknownException.

        Parameters
        ----------
        message : str
            Message to provide.
        """
        self.message = message


class SlaveNotReachableException(Exception):
    """Exception to be thrown when a slave is not reachable."""

    def __init__(self, message: str) -> None:
        """Create a SlaveNotReachableException.

        Parameters
        ----------
        message : str
            Message to provide.
        """

        self.message = message


class MissingComponentDefinitionException(Exception):
    """Exception to be thrown when a file included in a yaml config file could not be found."""

    def __init__(self, filename: str) -> None:
        """Create a MissingComponentDefinitionException.

        Parameters
        ----------
        filename : str
            File that could not be resolved.
        """

        self.filename = filename
