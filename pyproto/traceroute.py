from dataclasses import dataclass, field
from typing import List, Optional

from .protocols.icmp import ICMPCode, ICMPEcho, ICMPType
from .protocols.sockets import ICMPSocket
from .protocols.utils import get_logger

logger = get_logger("traceroute")


@dataclass
class Probe:
    seq: int
    addr: Optional[str]
    rtt: Optional[float]
    icmp_type: Optional[ICMPType] = None
    icmp_code: Optional[ICMPCode] = None


@dataclass
class Hop:
    hop: int
    probes: List[Probe] = field(default_factory=list)


def traceroute(
    dest: str,
    attempts=2,
    # interval=0.05,
    timeout=2,
    hop_start=1,
    max_hops=30,
    output=False,
):
    reached = False
    current_ttl = hop_start
    hops = List[Hop]

    while not reached and current_ttl <= max_hops:
        current_hop = {"addr": "*", "rtts": []}
        for attempt in range(attempts):
            try:
                with ICMPSocket(dest=dest, ttl=current_ttl) as s:
                    req = ICMPEcho(
                        icmp_type=ICMPType.ECHO_REQUEST,
                        icmp_code=ICMPCode.CODE_0,
                        seq=current_ttl * 10 + attempt,
                    )

                    s.send(req)
                    res, addr, rtt = s.receive(timeout=timeout)

                    if not res or not addr:
                        current_hop["rtts"].append(None)
                    else:
                        current_hop["addr"] = addr[0]
                        current_hop["rtts"].append(rtt)
            except OSError as e:
                logger.error(
                    "Unable to probe hop %d at attempt %d: %s", current_ttl, attempt, e
                )
                current_hop["rtts"].append(None)
        hops.append(current_hop)
        if output:
            rtt_str = " ".join(
                f"{rtt:.2f}" if rtt is not None else "*" for rtt in current_hop["rtts"]
            )
            print(f"{current_ttl:2} {current_hop['addr']} {rtt_str}")
        current_ttl += 1
        if current_hop["addr"] == dest:
            reached = True
    return hops
