from pyproto import traceroute

if __name__ == "__main__":
    print(traceroute(dest="8.8.8.8", count=2))
