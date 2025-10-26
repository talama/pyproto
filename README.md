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

- ### Traceroute example

  Traceroute must be run with admin privileges because it relies on raw socket functionalities.

  Example using the default output.

  ```python
  from pyproto import traceroute

  if __name__ == "__main__":
      traceroute(dest="8.8.8.8", output=True)
  ```

  ```bash
  ❯ sudo uv run -m examples.traceroute
  traceroute to 8.8.8.8, 30 hops max, 60 byte packets
   1  192.168.1.1  0.30ms 0.22ms 0.26ms
   2  *   *  *  *
   3  172.18.9.48  4.48ms 4.38ms 4.30ms
   4  172.18.8.222  5.11ms 4.72ms 4.79ms
   5  172.19.184.6  7.07ms 7.27ms 6.58ms
   6  172.19.177.26  8.97ms 8.26ms 8.65ms
   7  195.22.192.144  10.73ms 10.75ms 10.85ms
   8  72.14.204.72  8.80ms 8.92ms 8.24ms
   9  108.170.255.203  10.27ms 10.37ms 10.28ms
  10  108.170.233.57  8.96ms 8.77ms 9.07ms
  11  8.8.8.8  9.06ms 9.34ms 9.39ms
  ```

  Example with custom output:

  ```python
  from pyproto import traceroute

  if __name__ == "__main__":
      result = traceroute(dest="8.8.8.8")

      print(f"traceroute to {result.dest}")
      for hop in result.hops:
          print(hop.print_to_line())
  ```

  ```bash
  ❯ sudo uv run -m examples.traceroute
  traceroute to 8.8.8.8
    1 192.168.1.1  0.34ms 0.24ms 0.23ms
    2 *  *  *  *
    3 172.18.9.48  13.08ms 4.52ms 4.22ms
    4 172.18.8.222  6.07ms 4.80ms 4.87ms
    5 172.19.184.6  7.00ms 7.30ms 7.28ms
    6 172.19.177.26  8.68ms 8.79ms 8.95ms
    7 195.22.192.144  10.68ms 10.80ms 10.75ms
    8 72.14.204.72  9.00ms 8.72ms 12.62ms
    9 108.170.255.203  9.94ms 9.35ms 9.52ms
   10 108.170.233.57  8.75ms 8.83ms 8.84ms
   11 8.8.8.8  8.82ms 12.25ms 9.33ms
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
