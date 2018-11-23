import unittest
import struct
import actionSerializer
import depTree
import exception


class ActionSerializerTest(unittest.TestCase):

    def setUp(self):
        self.action = "start"
        self.component = {'name': 'testComp', 'host': 'testhost'}
        self.payload = [self.component, True, 123, False]

    def test_consistency(self):
        des = (self.action, self.payload)
        pick = actionSerializer.serialize_request(self.action, self.payload)

        fmt = '%ds %dx %ds' % (0, 4, len(pick) - 4)
        unused, lesser = struct.unpack(fmt, pick)
        res = actionSerializer.deserialize(lesser)

        self.assertEqual(des, res)


class DepTreeTest(unittest.TestCase):

    def setUp(self):
        self.comp_a = {'name': 'comp a'}
        self.comp_b = {'name': 'comp b'}
        self.comp_c = {'name': 'comp c'}
        self.comp_d = {'name': 'comp d'}

        self.node_a = depTree.Node(self.comp_a)
        self.node_b = depTree.Node(self.comp_b)
        self.node_c = depTree.Node(self.comp_c)
        self.node_d = depTree.Node(self.comp_d)

        self.node_a.add_edge(self.node_b)
        self.node_c.add_edge(self.node_b)
        self.node_b.add_edge(self.node_d)

    def test_dependencyList(self):
        res = []
        unres = []
        depTree.dep_resolve(self.node_a, res, unres)

        self.assertEqual(res, [self.node_d, self.node_b, self.node_a], "Dependency resolution is broken: wrong order!")

    def test_circular_dep_detection(self):
        with self.assertRaises(exception.CircularReferenceException):
            self.node_d.add_edge(self.node_a)
            depTree.dep_resolve(self.node_b, [], [])


if __name__ == '__main__':
    unittest.main()
