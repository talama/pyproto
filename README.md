# pyproto

Implementing TCP/IP stack protocols with python's socket library for fun and learning.

Currently implemented ICMP Echo Request/Reply and ICMP Destination Unreachable / Time Exceeded / Parameter Error

## Basic usage

- ### Ping

  ```python
  from pyproto import ping
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
