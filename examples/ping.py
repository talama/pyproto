import logging

from pyproto import ping, set_log_level

if __name__ == "__main__":
    set_log_level(logging.ERROR)
    result = ping(dest="8.8.8.8")
    print(result)
