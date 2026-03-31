import socket
import time
from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo
SERVICE_TYPE = "_cisc468p2p._tcp.local."

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def main():
    ip = get_local_ip()
    print(f"Local IP: {ip}")






if __name__ == "__main__":
    main()

