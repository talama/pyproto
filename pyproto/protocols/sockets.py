import socket
from enum import IntEnum
from time import time
from typing import Optional

from pyproto.protocols.icmp import ICMPEcho, ICMPError, ICMPType

from .utils import get_logger

logger = get_logger("ICMPSocket")


class SockType(IntEnum):
    RAW = socket.SOCK_RAW
    DGRAM = socket.SOCK_DGRAM


class ICMPSocket:
    """
    ICMP Sockets
    """

    def __init__(self, raw=True, dest: str = "127.0.0.1"):
        self.sock: Optional[socket.socket] = None
        self.sock_type = SockType.RAW if raw else SockType.DGRAM
        self.dest = dest
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
        self.sock.sendto(req.to_bytes(), (self.dest, 0))

    def parse_reply(self, res: bytes):
        data_size = len(res)
        if data_size < 28:  # IP header length + ICMP header
            logger.warning("Data size too small for a valid response.")
            return None

        ip_length = (res[0] & 0x0F) * 4  # IHL -> number of 32bits words
        icmp_header = res[ip_length:]

        if len(icmp_header) < 8:
            logger.warning("Data size too small for a valid response.")
            return None
        res_type = icmp_header[0]
        try:
            if res_type == ICMPType.ECHO_REPLY:
                return ICMPEcho.from_bytes(icmp_header)
            return ICMPError.from_bytes(icmp_header)
        except ValueError as e:
            logger.warning("Failed to parse ICMP reply: %s", e)
            return None

    def receive(self, timeout: float = 5):
        if not self.sock:
            raise OSError("No socket available.")
        start = time()
        try:
            self.sock.settimeout(timeout)
            res, addr = self.sock.recvfrom(1024)

            current_time = time()
            rtt = (current_time - start) * 1000
            reply = self.parse_reply(res)
            return reply, addr, rtt
        except socket.timeout:
            print("Timeout error.")
            return None, None, None
        except OSError:
            return None, None, None
