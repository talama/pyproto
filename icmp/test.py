from icmp.icmp import ICMPCode, ICMPEcho, ICMPType

header = ICMPEcho(type=ICMPType.ECHO_REQUEST, dest="127.0.0.1")
print(header)
