
class WindowNotFoundException(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(message)


class CircularReferenceException(Exception):
    def __init__(self, node1, node2):
        self.node1 = node1
        self.node2 = node2
