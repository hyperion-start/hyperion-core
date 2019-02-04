import logging
from graphviz import Digraph
from depTree import dep_resolve
from exception import *


###################
# Visualisation
###################
def draw_graph(control_center, unmet):
    """Generate and open a dependency graph pdf with graphviz.

    :param control_center: Manager holding the configuration to generate.
    :type control_center: ControlCenter
    :param unmet: List of unmet requirements
    :type unmet: List of str
    :return: None
    """

    deps = Digraph('Deps', strict=True, graph_attr={'splines': 'polyline', 'outputorder': 'edgesfirst', 'newrank': 'true'})
    deps.graph_attr.update(rankdir='RL')

    subgraphs = {}

    try:
        node = control_center.nodes.get('master_node')

        res = []
        unres = []
        dep_resolve(node, res, unres)
        res.remove(node)

        for requirement in unmet:
            deps.node(
                requirement,
                label='%s' % requirement,
                _attributes={'style': 'dashed', 'color': 'red', 'shape': 'box'}
            )

        for current in res:
            if not current.component['host'] in subgraphs:
                logging.debug("Creating host subgraph for %s" % current.component['host'])
                subgraphs[current.component['host']] = Digraph(
                    name='cluster_%s' % current.component['host'],
                    graph_attr={'style': 'filled', 'color': 'lightgrey',
                                'label': current.component['host']},
                    node_attr={'style': 'filled', 'color': 'white'}
                )

            shape = "box"

            if 'noauto'in current.component:
                shape = "doubleoctagon"

            subgraphs.get(current.component['host']).node(
                current.comp_id,
                label='<%s<BR /><FONT POINT-SIZE="8" color="darkgreen">%s</FONT>>' % tuple(current.comp_id.split('@')),
                _attributes={'style': 'filled', 'color': 'white', 'shape': shape}
            )

            for requirement in unmet:
                if current.component.get('requires') and requirement in current.component['requires']:
                    deps.edge(current.comp_id, requirement, 'missing', color='red')

            for sub_node_dep in get_direct_deps(current):
                parent = deps

                # Provide option to always show requires as node labels?
                edge_label = None
#                for requirement in current.component['requires']:
#                    if requirement in sub_node_dep.component['provides']:
#                        edge_label = requirement

                if current.component['host'] == sub_node_dep.comp_id.split('@')[1]:
                    parent = subgraphs.get(current.component['host'])

                if current.comp_id is not 'master_node':
                    parent.edge(current.comp_id, sub_node_dep.comp_id, edge_label)

    except CircularReferenceException as ex:
        control_center.logger.error('Detected circular dependency reference between %s and %s!' % (ex.node1, ex.node2))
        deps.edge(ex.node1, ex.node2, 'circular error', color='red')
        deps.edge(ex.node2, ex.node1, color='red')

    for subgraph in subgraphs:
        deps.subgraph(subgraphs.get(subgraph))

    logging.debug(deps)

    deps.view()


def get_direct_deps(node):
    """Return only direct dependencies of a node.

    :param node: Node to get dependencies from
    :type node: depTree.Node
    :return: List of direct dependencies
    :rtype: list of depTree.Node:
    """
    direct_deps = node.depends_on
    for sub_node_dep in node.depends_on:
        dep_res = []
        dep_unres = []
        dep_resolve(sub_node_dep, dep_res, dep_unres)
        dep_res.remove(sub_node_dep)

        [direct_deps.remove(x) for x in dep_res if x in direct_deps]

    return direct_deps
