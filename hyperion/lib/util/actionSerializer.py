import pickle
import struct
import logging
import hyperion.lib.util.config as config

from typing import Any, Union, Tuple, Mapping


def serialize_request(action: str, payload: list[Any]) -> bytes:
    """Serializes a request to an AbstractController derivate to be sent over socket.

    The four first bytes of the serialized message hold the message length, so that the receiver will be able to
    know how many bytes to read to get the whole message.

    Parameters
    ----------
    action : str
        Action to perform (take a look at ACTIONS dictionary for a list of valid actions)
    payload : list[Any]
        List that holds the parameters for the action to be called

    Returns
    -------
    str
        Serialized request
    """

    logger = logging.getLogger(__name__)
    logger.setLevel(config.DEFAULT_LOG_LEVEL)
    encoded = {"action": action}
    for i in range(len(payload)):
        encoded[f"arg_{i}"] = payload[i]
    pickled = pickle.dumps(encoded, protocol=5)  # 5 >= python 3.8
    return struct.pack(">I", len(pickled)) + pickled


def deserialize(message: bytes) -> Union[Tuple[None, Mapping[str, object]], Tuple[str, list[object]]]:
    """Deserialize an answer from an AbstractController derivate recieved as tcp message over socket.

    If the message does not hold an action type it is treated as socket log record.

    Parameters
    ----------
    message : str
        Unprocessed message received from another process.

    Returns
    -------
    Union[Tuple[None, str], Tuple[str, list[Any]]]
        Either returns action and arguments or just the received message in case no action can be retrieved.
    """

    logger = logging.getLogger(__name__)
    logger.setLevel(config.DEFAULT_LOG_LEVEL)
    unpickled = pickle.loads(message)

    # logger.debug("Decoding message: %s" % unpickled)
    args = []
    action = unpickled.get("action")
    if action:
        for index in range(len(unpickled) - 1):
            args.append(unpickled.get(f"arg_{index}"))
        # logger.debug("Got action: %s and args: %s" % (action, args))
        return action, args
    else:
        return None, unpickled


# TODO: These logger outputs need a lower level that DEBUG (TRACE?) which sadly does not exist by default
