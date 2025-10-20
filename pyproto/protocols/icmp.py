import struct
from dataclasses import dataclass
from enum import IntEnum
from time import time

from .utils import compute_checksum, get_identifier, get_logger, get_random_message

logger = get_logger("ICMPEcho")


class ICMPType(IntEnum):
    ECHO_REQUEST = 8
    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12


class ICMPCode(IntEnum):
    CODE_0 = 0
    CODE_1 = 1
    CODE_2 = 2
    CODE_3 = 3
    CODE_4 = 4
    CODE_5 = 5


# Echo or Echo Reply Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |     Code      |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           Identifier          |        Sequence Number        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Data ...
#    +-+-+-+-+-


@dataclass
class ICMPEcho:
    """
    ICMP Echo Request / Reply
    """

    type: ICMPType
    code: ICMPCode = ICMPCode.CODE_0
    identifier: int | None = None
    seq: int = 1
    data: bytes | None = None

    def __post_init__(self):
        if self.data is None:
            self.data = get_random_message(56)
        if self.identifier is None:
            self.identifier = get_identifier()
        if len(self.data) > 65500:
            logger.warning(
                "Data size of %d bytes is too big. Using random 56 byte message instead.",
                len(self.data),
            )
            self.data = get_random_message(56)
        if not (0 <= self.seq <= 0xFFFF):
            logger.warning(
                "Sequence number must be 0-65535, got %d. Using 1 instead", self.seq
            )
            self.seq = 1

        self.checksum = compute_checksum(self._pack_for_checksum())

    def __repr__(self):
        return (
            f"ICMPEcho(type={self.type.name}, code={self.code}, checksum={self.checksum}, "
            f"id={self.identifier}, seq={self.seq}, data_len={len(self.data) if self.data else 0})"
        )

    def _pack_for_checksum(self, chk: bool = False) -> bytes:
        """
        Pack header fields in bytes for checksum computation.
        Checksum set to 0 by default.
        If chk == True the computation use the packet checksum value instead.
        """
        assert self.data is not None
        checksum = self.checksum if chk else 0
        return (
            struct.pack(
                "!BBHHH",
                int(self.type),
                int(self.code),
                checksum,
                self.identifier,
                self.seq,
            )
            + self.data
        )

    def to_bytes(self) -> bytes:
        """
        Return raw ICMP packet (header + payload)
        """
        assert self.data is not None

        return (
            struct.pack(
                "!BBHHH",
                int(self.type),
                int(self.code),
                self.checksum,
                self.identifier,
                self.seq,
            )
            + self.data
        )

    def verify_checksum(self):
        """
        Verify the packet checksum
        """
        header_bytes = self._pack_for_checksum(chk=True)
        checksum = compute_checksum(header_bytes)
        return checksum == 0xFFFF

    @classmethod
    def from_bytes(cls, raw_data):
        """
        Cretates a ICMPEcho obj from a raw packet in bytes.
        """
        data_size = len(raw_data)
        if data_size > 65508:
            logger.error(
                "Packet size too large: %d bytes. Maximum payload size allowed is 65500 bytes",
                data_size,
            )
            return None

        if data_size <= 8:
            logger.error(
                "Packet size of %d bytes is too small to be valid ICMP", data_size
            )
            return None

        try:
            echo_type, code, checksum, identifier, seq = struct.unpack(
                "!BBHHH", raw_data[:8]
            )
            data = raw_data[8:]

            echo_type = ICMPType(echo_type)
            if echo_type not in (ICMPType.ECHO_REQUEST, ICMPType.ECHO_REPLY):
                raise ValueError(f"Invalid ICMP type: {echo_type}")
            code = ICMPCode(code)
            if code != ICMPCode.CODE_0:
                logger.warning("Invalid ICMP code: %d. Using 0 instead", code)
                code = ICMPCode.CODE_0
            icmp_obj = cls(
                type=echo_type, code=code, identifier=identifier, seq=seq, data=data
            )
            if icmp_obj.checksum != checksum:
                raise ValueError("Computed checksum doesn't match.")
        except (ValueError, struct.error) as e:
            logger.error("Failed to parse ICMP packet: %s", e)
            return None

        return icmp_obj
