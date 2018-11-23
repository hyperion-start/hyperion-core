import unittest
import struct
import actionSerializer


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


if __name__ == '__main__':
    unittest.main()
