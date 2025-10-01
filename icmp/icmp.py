import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum

from utils import helpers


class ICMPType(IntEnum):
    """
    ICMP Types.
    """

    ECHO_REQUEST = 8
    ECHO_REPLY = 0


class ICMPCode(IntEnum):
    """
    ICMP Codes.
    """

    CODE_0 = 0


@dataclass
class ICMPHeader(ABC):
    """
    ICMP header.
    Abstract class frome which each specific header
    inherits from.
    """

    type: ICMPType
    code: ICMPCode
    checksum: int = field(init=False, default=0)

    @abstractmethod
    def _pack_for_checksum(self) -> bytes:
        """
        Must be implemented by subclasses: return bytes for checksum computation
        including all header fields + payload.
        """
        pass

    def compute_checksum(self) -> int:
        """
        Checksum computation.
        One's complement sum of header's file + payload'
        """

        data = self._pack_for_checksum()
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            s += word
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    @abstractmethod
    def to_bytes(self) -> bytes:
        """
        Return raw ICMP packet (header + payload)
        """
        pass


@dataclass
class ICMPEcho(ICMPHeader):
    """
    ICMP header for echo message / reply
    """

    dest: str
    seq: int = 1
    code: ICMPCode = ICMPCode.CODE_0
    data_size: int = 56
    data: bytes | None = None
    ttl: int = 64
    time = 0
    id: int | None = None

    def __post_init__(self):
        self.code = ICMPCode.CODE_0
        if self.id is None:
            self.id = helpers.get_id()
        if self.data is None:
            self.data = helpers.get_random_message(self.data_size)
        self.checksum = self.compute_checksum()

    def _pack_for_checksum(self) -> bytes:
        assert self.data is not None
        # header with checksum=0 + payload
        return (
            struct.pack("!BBHHH", self.type, self.code, 0, self.id, self.seq)
            + self.data
        )

    def to_bytes(self) -> bytes:
        """
        Return raw ICMP packet (header + payload)
        """
        assert self.data is not None
        return (
            struct.pack(
                "!BBHHH", self.type, self.code, self.checksum, self.id, self.seq
            )
            + self.data
        )
