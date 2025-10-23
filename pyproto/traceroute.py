from time import sleep

from .protocols.icmp import ICMPCode, ICMPEcho, ICMPType
from .protocols.sockets import ICMPSocket
from .protocols.utils import get_logger

logger = get_logger("traceroute")


def traceroute(dest, count=2, interval=1, timeout=1, max_hops=30, start_hop=1, port=0):
    """
    tracks  the  route packets taken from an IP network on their way to a given host.
    It utilizes the IP protocol's time to live (TTL) field
    and attempts to elicit an ICMP TIME_EXCEEDED response from each gateway along the path to the host.
    """

    with ICMPSocket(dest=dest, ttl=start_hop, port=port) as s:
        reached = False
        hops = []
        current_ttl = start_hop

        while not reached and current_ttl <= max_hops:
            sent = 0

            for seq in range(count):
                try:
                    if seq > 0:
                        sleep(interval)
                    req = ICMPEcho(
                        icmp_type=ICMPType.ECHO_REQUEST,
                        icmp_code=ICMPCode.CODE_0,
                        seq=seq,
                    )

                    s.send(req)
                    sent += 1

                    res, addr, rtt = s.receive(timeout=timeout)
                    print(addr)
                except KeyboardInterrupt:
                    return 0
                except OSError:
                    logger.error("Failed to send icmp echo message.")
