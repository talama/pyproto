import socket

from .icmp import ICMPEcho, ICMPType
from .sockets import ICMPSocket

pkt = ICMPEcho(ICMPType.ECHO_REQUEST)

# with ICMPSocket(dest="8.8.8.8") as s:
#     s.send(pkt)
#     reply, addr, rtt = s.receive()
#     print(f"Received {reply} from {addr} in time={rtt:.2f}ms")

# with ICMPSocket(dest="192.0.2.123") as s:
#     # if s.sock is not None:
#     #     s.sock.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)
#     s.send(pkt)
#     reply, addr, rtt = s.receive()
#     if reply is None:
#         print("No reply")
#     else:
#         print(f"Received {reply} from {addr} in time={rtt:.2f}ms")

with ICMPSocket(dest="8.8.8.8") as s:
    if s.sock is not None:
        s.sock.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)
    s.send(pkt)
    reply, addr, rtt = s.receive()
    if reply is None:
        print("No reply")
    else:
        print(f"Received {reply} from {addr} in time={rtt:.2f}ms")
