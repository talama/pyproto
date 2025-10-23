import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Self

from .utils import get_identifier, get_logger, get_random_message

logger = get_logger("ICMP")


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
class ICMP(ABC):
    """
    ICMP base abstract class.
    """

    icmp_type: ICMPType
    icmp_code: ICMPCode

    def __post_init__(self):
        pass

    @abstractmethod
    def _pack_for_checksum(self, chk=False) -> bytes:
        """
        Must be implemented by subclasses.
        Return bytes for checksum computation including all header fields + payload.
        If chk is True include checksum in the computation.
        If chk is False checksum is set to 0 in the computation.
        """
        pass

    def compute_checksum(self, header: bytes) -> int:
        """
        Checksum computation. Reference RFC 1071.
        """
        if len(header) % 2:
            header = b"\x00" + header

        checksum = 0
        for i in range(0, len(header), 2):
            word = (header[i] << 8) + header[i + 1]
            checksum += word
            checksum = (checksum & 0x0FFFF) + (checksum >> 16)

        return ~checksum & 0x0FFFF

    def verify_checksum(self):
        checksum = self.compute_checksum(self._pack_for_checksum(chk=True))
        return checksum == 0x0FFFF

    def to_bytes(self) -> bytes:
        """
        Return raw ICMP packet (header + payload)
        """
        return self._pack_for_checksum(chk=True)

    @classmethod
    @abstractmethod
    def from_bytes(cls, raw_data: bytes) -> Self | None:
        """
        Must be implemented by subclasses.
        Creates a ICMP object from raw ICMP packet
        """
        pass


@dataclass
class ICMPEcho(ICMP):
    """
    ICMP Echo Request / Reply
    """

    icmp_code: ICMPCode = field(default=ICMPCode.CODE_0)
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
        self.checksum = self.compute_checksum(self._pack_for_checksum())

    def __repr__(self):
        return (
            f"ICMPEcho(type={self.icmp_type.name}, code={self.icmp_code}, checksum={self.checksum}, "
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
                int(self.icmp_type),
                int(self.icmp_code),
                checksum,
                self.identifier,
                self.seq,
            )
            + self.data
        )

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> Self | None:
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
            icmp_type, code, checksum, identifier, seq = struct.unpack(
                "!BBHHH", raw_data[:8]
            )
            data = raw_data[8:]

            icmp_type = ICMPType(icmp_type)
            if icmp_type not in (ICMPType.ECHO_REQUEST, ICMPType.ECHO_REPLY):
                raise ValueError(f"Invalid ICMP type: {icmp_type}")
            icmp_code = ICMPCode(code)
            if icmp_code != ICMPCode.CODE_0:
                logger.warning("Invalid ICMP code: %d. Using 0 instead", icmp_code)
                icmp_code = ICMPCode.CODE_0
            icmp_obj = cls(
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                identifier=identifier,
                seq=seq,
                data=data,
            )
            if icmp_obj.checksum != checksum:
                raise ValueError("Computed checksum doesn't match.")
        except (ValueError, struct.error) as e:
            logger.error("Failed to parse ICMP packet in ICMPEcho: %s", e)
            return None

        return icmp_obj


# Destination Unreachable Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |     Code      |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                             unused                            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |      Internet Header + 64 bits of Original Data Datagram      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Time Exceeded Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |     Code      |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                             unused                            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |      Internet Header + 64 bits of Original Data Datagram      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Parameter Problem Message
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type      |     Code      |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |    Pointer    |                   unused                      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |      Internet Header + 64 bits of Original Data Datagram      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


@dataclass
class ICMPError(ICMP):
    """
    ICMP Destination Unreachable
    ICMP Time Exceeded
    ICMP Parameter Problem
    """

    data: bytes
    pointer: int | None = None

    def __post_init__(self):
        self.checksum = self.compute_checksum(self._pack_for_checksum())
        self.code_msg: str | None = None

    def __repr__(self) -> str:
        msg = self.code_msg if self.code_msg is not None else self.icmp_code
        if self.pointer is None:
            return f"ICMPError(type={self.icmp_type.name}, code={msg}, checksum={self.checksum}, data_len={len(self.data)})"
        return f"ICMPError(type={self.icmp_type.name}, code={msg}, checksum={self.checksum}, pointer={self.pointer}, data_len={len(self.data)})"

    def _pack_for_checksum(self, chk: bool = False) -> bytes:
        """
        Pack header fields in bytes for checksum computation.
        Checksum set to 0 by default.
        If chk == True the computation use the packet checksum value instead.
        """

        checksum = self.checksum if chk else 0
        if self.icmp_type == ICMPType.PARAMETER_PROBLEM:
            return (
                struct.pack(
                    "!BBHB3x",
                    int(self.icmp_type),
                    int(self.icmp_code),
                    checksum,
                    self.pointer,
                )
                + self.data
            )
        return (
            struct.pack(
                "!BBH4x",
                int(self.icmp_type),
                int(self.icmp_code),
                checksum,
            )
            + self.data
        )

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> Self | None:
        """
        Cretates a ICMPError obj from a raw packet in bytes.
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
            icmp_type = ICMPType(raw_data[0])
            data = raw_data[8:]
            error_obj = None
            if icmp_type == ICMPType.PARAMETER_PROBLEM:
                icmp_code, checksum, pointer = struct.unpack("!BHB", raw_data[1:5])
                icmp_code = ICMPCode(icmp_code)
                error_obj = cls(
                    icmp_type=icmp_type, icmp_code=icmp_code, pointer=pointer, data=data
                )
            else:
                icmp_code, checksum = struct.unpack("!BH", raw_data[1:4])
                icmp_code = ICMPCode(icmp_code)
                code_msg = ""
                if icmp_type == ICMPType.TIME_EXCEEDED:
                    match icmp_code:
                        case ICMPCode.CODE_0:
                            code_msg = "Time to live exceeded in transit"
                        case ICMPCode.CODE_1:
                            code_msg = "Fragment reassembly time exceeded."
                if icmp_type == ICMPType.DESTINATION_UNREACHABLE:
                    match icmp_code:
                        case ICMPCode.CODE_0:
                            code_msg = "Net unreachable."
                        case ICMPCode.CODE_1:
                            code_msg = "Host unreachable."
                        case ICMPCode.CODE_2:
                            code_msg = "Protocol unreachable"
                        case ICMPCode.CODE_3:
                            code_msg = "Port Unreachable"
                        case ICMPCode.CODE_4:
                            code_msg = "Fragmentation needed."
                        case ICMPCode.CODE_5:
                            code_msg = "Source route failed."
                error_obj = cls(
                    icmp_type=icmp_type, icmp_code=icmp_code, pointer=None, data=data
                )
                error_obj.code_msg = code_msg
            if error_obj.checksum != checksum:
                raise ValueError("Computed checksum doesn't match.")
            return error_obj

        except (ValueError, struct.error) as e:
            logger.error("Failed to parse ICMP packet in ICMPError: %s", e)
            return None
