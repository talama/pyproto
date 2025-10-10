import socket

from .icmp import ICMPEcho, ICMPType
from .sockets import ICMPSocket

pkt = ICMPEcho(ICMPType.ECHO_REQUEST)

with ICMPSocket(dest="8.8.8.8") as s:
    s.send(pkt)
    reply, addr, rtt = s.receive()
    print(f"Received {reply} from {addr} in time={rtt:.2f}ms")
