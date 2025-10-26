from collections import defaultdict
from dataclasses import dataclass, field
from time import sleep
from typing import Dict, List, Optional

from .protocols.icmp import ICMPCode, ICMPEcho, ICMPType
from .protocols.sockets import ICMPSocket
from .protocols.utils import get_identifier, get_logger, get_random_message

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

    @property
    def addr(self) -> Optional[str]:
        """
        First valid probe address if any.
        """
        for p in self.probes:
            if p.addr:
                return p.addr
        return None

    @property
    def address_rtts(self):
        res: Dict[str, List[Optional[float]]] = defaultdict(list)
        for p in self.probes:
            if p.addr:
                res[p.addr].append(p.rtt)
        return res

    def print_to_line(self):
        out = ""
        for addr, rtts in self.address_rtts.items():
            out += f" {addr}"
            for rtt in rtts:
                out += f" {rtt:.2f}ms" if rtt is not None else " *"
        return out


@dataclass
class TracerouteResult:
    dest: str
    hops: List[Hop] = field(default_factory=list)


def traceroute(
    dest: str,
    attempts=3,
    interval=0.5,
    timeout=1,
    hop_start=1,
    max_hops=30,
    output=False,
):
    reached = False
    current_ttl = hop_start
    result = TracerouteResult(dest=dest)
    seq = 1

    while not reached and current_ttl <= max_hops:
        current_hop = Hop(current_ttl)
        for attempt in range(attempts):
            current_probe = Probe(addr=None, rtt=None, seq=seq)
            with ICMPSocket(dest=dest, ttl=current_ttl) as s:
                try:
                    req = ICMPEcho(
                        icmp_type=ICMPType.ECHO_REQUEST,
                        icmp_code=ICMPCode.CODE_0,
                        seq=seq,
                    )
                    s.send(req)
                    res, addr, rtt = s.receive(timeout=timeout)
                    if res is not None and addr is not None:
                        current_probe = Probe(
                            addr=addr[0],
                            rtt=rtt,
                            seq=seq,
                            icmp_type=res.icmp_type,
                            icmp_code=res.icmp_code,
                        )

                    current_hop.probes.append(current_probe)
                    if (
                        current_probe.addr == dest
                        and current_probe.icmp_type == ICMPType.ECHO_REPLY
                    ):
                        reached = True
                        break
                    seq += 1
                    sleep(interval)
                except OSError as e:
                    logger.error(
                        "Unable to probe hop %d at attempt %d: %s",
                        current_ttl,
                        attempt,
                        e,
                    )
                    current_hop.probes.append(Probe(addr=None, rtt=None, seq=seq))
        result.hops.append(current_hop)
        if output:
            if current_hop.addr is None:  # all probes timed out
                print(
                    f"{current_ttl:2d} {' *  ':} {'  '.join('*' for _ in range(attempts))}"
                )
            else:
                print(f"{current_ttl:2d} {current_hop.print_to_line()}")
        current_ttl += 1
    return result
