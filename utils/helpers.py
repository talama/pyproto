from os import getpid
from random import choices


def get_random_message(size):
    """
    Returns a random message of size bytes
    """

    message = choices(
        b"abcdefghijklmnopqrstuvwxyz" b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" b"1234567890",
        k=size,
    )
    return bytes(message)


def get_id():
    """
    Generate a unique identifier.
    """
    return getpid() & 0xFFFF
