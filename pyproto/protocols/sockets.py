import socket
from enum import IntEnum
from time import time
from typing import Optional

from pyproto.protocols.icmp import ICMPEcho

from .utils import get_logger

logger = get_logger("ICMPSocket")


class SockType(IntEnum):
    RAW = socket.SOCK_RAW
    DGRAM = socket.SOCK_DGRAM


class ICMPSocket:
    """
    ICMP Sockets
    """

    def __init__(self, raw=True, destination: str = "127.0.0.1"):
        self.sock: Optional[socket.socket] = None
        self.sock_type = SockType.RAW if raw else SockType.DGRAM
        self.destination = destination
        try:
            self._create_socket(self.sock_type)
        except PermissionError:
            logger.warning(
                "You need admin privileges to use raw sockets. Running as SOCK_DGRAM."
            )
            self._create_socket(sock_type=SockType.DGRAM)

    def __enter__(self):
        """
        Return this object.
        """
        return self

    def __exit__(self, type, value, traceback):
        """
        Call the close method.
        """
        self.close()

    def __del__(self):
        """
        Call the close method.
        """
        self.close()

    def close(self):
        """
        Close the socket.
        """
        if self.sock:
            self.sock.close()
            self.sock = None

    def _create_socket(self, sock_type: SockType):
        self.sock = socket.socket(
            family=socket.AF_INET, type=sock_type, proto=socket.IPPROTO_ICMP
        )

    def send(self, req: ICMPEcho):
        if not self.sock:
            raise OSError("No socket available.")
        req.icmp_time = time()
        self.sock.sendto(req.to_bytes(), (self.destination, 0))
