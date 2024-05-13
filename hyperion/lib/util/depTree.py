from hyperion.lib.util.exception import CircularReferenceException
from hyperion.lib.util.types import Component
from typing_extensions import Self

class Node(object):
    """This class models a component as node of a dependency tree."""

    pass

    def __init__(self, comp: Component) -> None:
        """Initialize node for component `comp`.

        Parameters
        ----------
        comp : Component
            Component to create a node for.
        """

        self.component = comp
        self.depends_on: list[Node] = []
        self.comp_id = comp["id"]

    def add_edge(self, node: Self) -> None:
        """Add a node as dependency.

        Parameters
        ----------
        node: Node
            Node to add as dependency
        """

        self.depends_on.append(node)


def dep_resolve(node: Node, resolved: list[Node], unresolved: list[Node]) -> None:
    """Recursively generate a list of all dependencies for `node`.

    Parameters
    ----------
    node : Node
        Node to resolve dependencies for
    resolved : list[Node]
        List of already resolved nodes
    unresolved : list[Node]
        List of unresolved nodes

    Raises
    ------
    CircularReferenceException
        If the config contains at least one node with a circular dependency.
    """

    unresolved.append(node)
    for edge in node.depends_on:
        if edge not in resolved:
            if edge in unresolved:
                raise CircularReferenceException(node.comp_id, edge.comp_id)
            dep_resolve(edge, resolved, unresolved)
    resolved.append(node)
    unresolved.remove(node)
