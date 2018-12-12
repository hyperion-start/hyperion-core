import pickle
import struct
import logging


def serialize_request(action, payload):
    """Serializes a request to an AbstractController derivate to be sent over socket.

    The four first bytes of the serialized message hold the message length, so that the receiver will be able to
    know how many bytes to read to get the whole message.

    :param action: Action to perform (take a look at ACTIONS dictionary for a list of valid actions)
    :type action: str
    :param payload: List that holds the parameters for the action to be called
    :type payload: List of Object
    :return: Serialized request
    :rtype: str
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    encoded = {'action': action}
    for i in range(len(payload)):
        encoded['arg_%s' % i] = payload[i]
    # logger.debug("Encoded to %s" % encoded)
    pickled = pickle.dumps(encoded)
    return struct.pack('>I', len(pickled)) + pickled


def deserialize(message):
    """Deserialize an answer from an AbstractController derivate recieved as tcp message over socket.

    If the message does not hold an action type it is treated as socket log record.

    :param message: Recevied message
    :type message: str
    :return: Tuple of action and argument list
    :rtype: tuple of str and list of Object
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    unpickled = pickle.loads(message)

    # logger.debug("Decoding message: %s" % unpickled)
    args = []
    action = unpickled.get('action')
    if action:
        for index in range(len(unpickled)-1):
            args.append(unpickled.get('arg_%s' % index))
        # logger.debug("Got action: %s and args: %s" % (action, args))
        return action, args
    else:
        return None, unpickled

# TODO: These logger outputs need a lower level that DEBUG (TRACE?) which sadly does not exist by default
