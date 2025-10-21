from time import sleep
from typing import List

from pyproto.protocols.icmp import ICMPEcho, ICMPError, ICMPType
from pyproto.protocols.sockets import ICMPSocket
from pyproto.protocols.utils import get_logger

logger = get_logger("Ping")


def ping(dest: str, port: int = 0, count=4, interval=1, timeout=2, ttl=64):
    """
    Simple ping implementation.
    Send icmp Echo request packets to a network host
    and parse the response if any.
    """

    pkt_sent = 0
    pkt_recv = 0
    pkt_lost = 0
    rtts: List[float] = []

    print(f"PING {dest}")

    with ICMPSocket(dest=dest, port=port) as s:
        s.set_ttl(ttl)
        for seq in range(count):
            if seq > 0:
                sleep(interval)

            req = ICMPEcho(icmp_type=ICMPType.ECHO_REQUEST, seq=seq)
            try:
                s.send(req)
                pkt_sent += 1

                res, addr, rtt = s.receive(timeout=timeout)
                if res is None:
                    pkt_lost += 1
                    continue
                match res.icmp_type:
                    case ICMPType.ECHO_REPLY:
                        assert res.data is not None
                        assert rtt is not None
                        pkt_recv += 1
                        rtts.append(rtt)
                        print(
                            f"{len(res.data)} from {dest}: icmp_seq={seq} time={rtt:.2f} ms"
                        )
                    case t if t in (
                        ICMPType.TIME_EXCEEDED,
                        ICMPType.DESTINATION_UNREACHABLE,
                    ):
                        assert isinstance(res, ICMPError)
                        pkt_lost += 1
                        print(
                            f"From {addr[0] if addr else '()'} icmp_seq={seq} {res.code_msg}"
                        )

            except OSError:
                logger.error("Failed to send icmp echo message")
