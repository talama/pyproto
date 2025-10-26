from pyproto import traceroute

if __name__ == "__main__":
    result = traceroute(dest="8.8.8.8", output=True)

    # print(f"traceroute to {result.dest}")
    # for hop in result.hops:
    #     print(hop.to_line())
