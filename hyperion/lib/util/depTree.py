from exception import CircularReferenceException


class Node(object):
    """This class models a component as node of a dependency tree."""
    pass

    def __init__(self, comp):
        """Initialize node for component ``comp``.

        :param comp: Component to create a node for
        :type comp: dict
        """

        self.component = comp
        self.depends_on = []
        self.comp_name = comp['name']

    def add_edge(self, node):
        """Add a node as dependency.

        :param node: Node to add as dependency
        :type node: Node
        :return: None
        """

        self.depends_on.append(node)


def dep_resolve(node, resolved, unresolved):
    """Recursively generate a list of all dependencies for ``node``

    :param node: Node to resolve dependencies for
    :type node: Node
    :param resolved: List of already resolved nodes
    :type resolved: List of Node
    :param unresolved: List of unresolved nodes
    :type unresolved: List of Node
    :return: List containing all dependencies of ``node``
    :rtype: List of Node
    """

    unresolved.append(node)
    for edge in node.depends_on:
        if edge not in resolved:
            if edge in unresolved:
                raise CircularReferenceException(node.comp_name, edge.comp_name)
            dep_resolve(edge, resolved, unresolved)
    resolved.append(node)
    unresolved.remove(node)