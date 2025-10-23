from dataclasses import dataclass, field
from time import sleep
from typing import List, Optional

from pyproto import ICMPEcho, ICMPError, ICMPSocket, ICMPType, get_logger

logger = get_logger("Ping")


@dataclass
class PingPacket:
    """
    Dataclass to store informations about a icmp packet.
    """

    icmp_type: Optional[str]
    icmp_code: Optional[str]
    seq: int
    rtt: Optional[float]
    success: bool


@dataclass
class PingResult:
    """
    Dataclass to store results from a ping run.
    """

    dest: str
    sent: int = 0
    recvd: int = 0
    lost: int = 0
    rtts: List[float] = field(default_factory=list)
    packets: List[PingPacket] = field(default_factory=list)


def ping(
    dest: str, port: int = 0, count=4, interval=1, timeout=1, ttl=64, output=False
):
    """
    Simple ping implementation.
    Send icmp Echo request packets to a network host
    and parse the response if any.
    """

    rtts: List[float] = []

    if output:
        print(f"PING {dest}")

    result = PingResult(dest=dest)
    with ICMPSocket(dest=dest, port=port, ttl=ttl) as s:
        for seq in range(count):
            try:
                if seq > 0:
                    sleep(interval)

                req = ICMPEcho(icmp_type=ICMPType.ECHO_REQUEST, seq=seq)
                s.send(req)
                result.sent += 1

                res, addr, rtt = s.receive(timeout=timeout)
                if not res or not rtt:
                    result.lost += 1
                    result.packets.append(
                        PingPacket(
                            icmp_type=None,
                            icmp_code=None,
                            seq=seq,
                            rtt=None,
                            success=False,
                        )
                    )
                    continue
                match res.icmp_type:
                    case ICMPType.ECHO_REPLY:
                        assert isinstance(res, ICMPEcho)
                        result.recvd += 1
                        result.rtts.append(rtt)
                        result.packets.append(
                            PingPacket(
                                icmp_type=res.icmp_type.name,
                                icmp_code=res.icmp_code.name,
                                seq=res.seq,
                                rtt=rtt,
                                success=True,
                            )
                        )
                        if output:
                            print(
                                f"{len(res.data) if res.data else '0'} bytes from {dest}: icmp_seq={seq} time={rtt:.2f} ms"
                            )
                    case t if t in (
                        ICMPType.TIME_EXCEEDED,
                        ICMPType.DESTINATION_UNREACHABLE,
                    ):
                        assert isinstance(res, ICMPError)
                        result.lost += 1
                        result.packets.append(
                            PingPacket(
                                icmp_type=res.icmp_type.name,
                                icmp_code=res.icmp_code.name,
                                seq=seq,
                                rtt=rtt,
                                success=False,
                            )
                        )
                        if output:
                            print(
                                f"From {addr[0] if addr else '()'} icmp_seq={seq} {res.code_msg}"
                            )
            except KeyboardInterrupt:
                return result

            except OSError:
                logger.error("Failed to send icmp echo message")
        return result
