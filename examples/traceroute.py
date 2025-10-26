from pyproto import traceroute

if __name__ == "__main__":
    hops = traceroute(dest="8.8.8.8", output=True)
