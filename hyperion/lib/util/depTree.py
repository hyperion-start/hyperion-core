from exception import CircularReferenceException


class Node(object):
    pass

    def __init__(self, comp):
        self.component = comp
        self.depends_on = []
        self.comp_name = comp['name']

    def add_edge(self, node):
        self.depends_on.append(node)


def dep_resolve(node, resolved, unresolved):
    unresolved.append(node)
    for edge in node.depends_on:
        if edge not in resolved:
            if edge in unresolved:
                raise CircularReferenceException(node.comp_name, edge.comp_name)
            dep_resolve(edge, resolved, unresolved)
    resolved.append(node)
    unresolved.remove(node)