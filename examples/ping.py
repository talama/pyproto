import logging

from pyproto import ping, set_log_level

if __name__ == "__main__":
    set_log_level(logging.ERROR)
    result = ping(dest="8.8.8.8", output=True)
    packet_loss = float(result.lost / result.sent) * 100
    print("\n\n")
    print(f"--- {result.dest} ping statistics ---")
    print(
        f"{result.sent} packet transmitted, {result.recvd} received, {packet_loss:.0f}% packet loss."
    )
    for p in result.packets:
        print(p)
