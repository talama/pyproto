import socket

from .icmp import ICMPEcho, ICMPType

pkt = ICMPEcho(ICMPType.ECHO_REQUEST)
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
    s.sendto(pkt.to_bytes(), ("8.8.8.8", 0))
    res = s.recv(1024)
    ip_length = (res[0] & 0x0F) * 4
    icmp_raw = res[ip_length:]
    icmp_pkt = ICMPEcho.from_bytes(icmp_raw)
    print(icmp_pkt)
