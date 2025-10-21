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
