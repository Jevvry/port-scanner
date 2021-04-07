import socket
import struct
import threading

print_lock = threading.Lock()
ICMP_ECHO = 8


def scan_port(ip, port):
    sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_connect = sock_tcp.connect_ex((ip, port))
    if tcp_connect == 0:
        with print_lock:
            print('TCP port :', port, ' is open.')
    sock_tcp.close()
    scan_udp_port(ip, port)


def scan_udp_port(ip, port):
    sock_upd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_connect = sock_upd.connect_ex((ip, port))
    if udp_connect == 0:
        sock_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock_icmp.sendto(make_icmp_package(port), (ip, port))
        sock_icmp.settimeout(0.5)
        try:
            response = sock_icmp.recv(2048)
            if our_icmp_response(response):
                with print_lock:
                    print('UDP port :', port, ' is open.')
        except:
            pass
        finally:
            sock_icmp.close()
    sock_upd.close()


def our_icmp_response(data):
    icmp_header = data[20:28]
    type, code, checksum, p_id, sequence = struct.unpack('BBHHH', icmp_header)
    return type == 0 and code == 0


def make_icmp_package(port):
    checksum = 0

    header = struct.pack(
        "!BBHHH", ICMP_ECHO, 0, checksum, threading.current_thread().ident, port)

    padBytes = []
    startVal = 0x42
    for i in range(startVal, startVal + 55):
        padBytes += [(i & 0xff)]
    data = bytes(padBytes)

    checksum = calc_checksum(header + data)

    header = struct.pack(
        "!BBHHH", ICMP_ECHO, 0, checksum, threading.current_thread().ident, port)

    packet = header + data

    return packet


def calc_checksum(packet: bytes) -> int:
    words = [int.from_bytes(packet[_:_ + 2], "big") for _ in range(0, len(packet), 2)]
    checksum = sum(words)
    while checksum > 0xffff:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return 0xffff - checksum


if __name__ == '__main__':
    ip = input("Ip address:")
    rng = input("Port range in format start,stop: ").split(",")
    start, stop = int(rng[0]), int(rng[1])
    pool = []
    print()
    for i in range(start, stop):
        thread = threading.Thread(target=scan_port, args=(ip, i))
        pool.append(thread)
        thread.start()
    for i in pool:
        i.join()
