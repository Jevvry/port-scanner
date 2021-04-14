import socket
import threading

import packageFactory

print_lock = threading.Lock()
recognizers = [(packageFactory.build_http_packet, packageFactory.is_http_package, "HTTP"),
               (packageFactory.build_smtp_packet, packageFactory.is_smtp_package, "SMTP"),
               (packageFactory.build_pop3_packet, packageFactory.is_pop3_package, "POP3"),
               (packageFactory.build_dns_package, packageFactory.is_dns_package, "DNS"),
               (packageFactory.build_ntp_packet, packageFactory.is_ntp_package, "SNTP")]


def scan_port(ip, port):
    sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_connect = sock_tcp.connect_ex((ip, port))
    if tcp_connect == 0:
        with print_lock:
            print('TCP port :', port, ' is open', end=" ")
            print(scan_application_layer(sock_tcp))
    sock_tcp.close()
    scan_udp_port(ip, port)


def scan_application_layer(sock):
    for builder, recognizer, answer in recognizers:
        try:
            sock.settimeout(0.05)
            sock.send(builder())
            response = sock.recv(2048)
            if recognizer(response):
                return answer
        except:
            pass
    return ""


def scan_udp_port(ip, port):
    sock_upd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_connect = sock_upd.connect_ex((ip, port))
    if udp_connect == 0:
        with print_lock:
            print('UDP port :', port, ' is open', end=" ")
            application_layer = scan_application_layer(sock_upd)
            if application_layer == "":
                print("or filtered")
            else:
                print(scan_application_layer(sock_upd))
    sock_upd.close()


if __name__ == '__main__':
    ip = input("Ip address:")
    rng = input("Port range in format start,stop: ").split(",")
    start, stop = int(rng[0]), int(rng[1])
    pool = []
    print()

    for port in range(start, stop + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port))
        pool.append(thread)
        thread.start()
    for i in pool:
        i.join()

    #  ntp3.stratum2.ru /sntp 25
    #  vk.com /http 80
    #  8.8.8.8 /dns 53
    #  smtp.gmail.com /smtp 123
    #  pop.masterhost.ru /pop3 110
