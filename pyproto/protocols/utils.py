import logging
from os import getpid
from random import choices


def get_logger(name: str = __name__) -> logging.Logger:
    """Create a custom logger by name"""
    logger = logging.getLogger(name)

    # Avoid adding multiple handlers if logger is requested multiple times
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(name)s - %(message)s",
            style="%",
            datefmt="%d-%m-%Y %H:%M:%S",
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    logger.propagate = True
    return logger


def set_log_level(level: int):
    """
    Set the logging level for all pyproto loggers.

    Usage example:
    import logging
    from pyproto import set_log_level
    set_log_level(logging.ERROR)
    """
    logging.basicConfig(level=level)


def compute_checksum(header: bytes) -> int:
    """
    Checksum computation. Reference RFC 1071.

    Adjacent octets to be checksummed are paired to form 16-bit
    integers, and the 1's complement sum of these 16-bit integers is
    formed.

    For this computation the checksum field of the header should be 0.

    To verify the cehcksum calculate the checksum with the actual checksum in the header.
    The sum over all 16-bit words (including the checksum field)
    should be 0xFFFF if the packet is correct.
    """

    # Add a one byte padding at the beginning if odd number of bytes
    if len(header) % 2:
        header = b"\x00" + header

    checksum = 0
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + header[i + 1]
        checksum += word
        checksum = (checksum & 0x0FFFF) + (checksum >> 16)

    return ~checksum & 0x0FFFF


def get_random_message(size: int) -> bytes:
    """
    Generate a random byte message
    """
    message = choices(
        b"ABCDEFGHIJKLMNOPQRSTUWXYZ" b"abcdefghijklmnopqrstuwxyz" b"0123456789", k=size
    )
    return bytes(message)


def get_identifier() -> int:
    """
    Generate unique 16bits identifier
    """
    identifier = getpid()
    return identifier & 0xFFFF
