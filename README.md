# pyproto

Implementing TCP/IP stack protocols with python's socket library for fun and learning.

Currently implemented ICMP Echo Request/Reply and ICMP Destination Unreachable / Time Exceeded / Parameter Error

## Basic usage

- ### Ping Example

  Raw sockets require admin privileges to avoid malicious use.

  If run without admin privileges pyproto sockets will defalut to DGRAM sockets.
  ICMP over DGRAM sockets support only a limited sets of options.

  ```python
  from pyproto import ping

  if __name__ == "__main__":
      result = ping(dest="8.8.8.8", output=True)
      packet_loss = float(result.lost / result.sent) * 100
      print("\n")
      print(f"--- {result.dest} ping statistics ---")
      print(
          f"{result.sent} packet transmitted, {result.recvd} received, {packet_loss:.0f}% packet loss."
      )
      [print(p) for p in result.packets]
  ```

  ```bash
  ❯ uv run -m examples.ping
  PING 8.8.8.8
  21-10-2025 22:41:10 - WARNING - ICMPSocket - You need admin privileges to use raw sockets. Running as SOCK_DGRAM.
  21-10-2025 22:41:10 - WARNING - ICMPSocket - ICMP DGRAM sockets only support Echo Request/Reply
  21-10-2025 22:41:10 - WARNING - ICMPSocket - Other ICMP types will not be sent or received.
  56 bytes from 8.8.8.8: icmp_seq=0 time=9.58 ms
  56 bytes from 8.8.8.8: icmp_seq=1 time=9.37 ms
  56 bytes from 8.8.8.8: icmp_seq=2 time=9.22 ms
  56 bytes from 8.8.8.8: icmp_seq=3 time=9.31 ms


  --- 8.8.8.8 ping statistics ---
  4 packet transmitted, 4 received, 0% packet loss.
  PingPacket(icmp_type='ECHO_REPLY', icmp_code='CODE_0', seq=0, rtt=9.57942008972168, success=True)
  PingPacket(icmp_type='ECHO_REPLY', icmp_code='CODE_0', seq=1, rtt=9.36746597290039, success=True)
  PingPacket(icmp_type='ECHO_REPLY', icmp_code='CODE_0', seq=2, rtt=9.21773910522461, success=True)
  PingPacket(icmp_type='ECHO_REPLY', icmp_code='CODE_0', seq=3, rtt=9.312629699707031, success=True)
  ```

- ### ICMPEcho / ICMPError / ICMPTYPE / ICMPCode

  ```python
  from pyproto import ICMPEcho, ICMPError, ICMPType, ICMPCode
  ```

  ICMPType / ICMPCode are enums containing the ICMP types/codes currently supported.

  ICMPEcho is the class implementing ICMP echo Reply/Reques.

  ICMPError is the class implementing the ICMP errors currently supported.

  Both classes inherit from an abstract parent class - ICMP.

  Both classes support obj creation FROM raw bytes and exporting TO raw bytes.

- ### ICMP Socket

  ```python
  from pyproto import ICMPSocket
  ```
