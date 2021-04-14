from scapy.layers.dns import *
from scapy.layers.http import *
from scapy.layers.ntp import *


def build_dns_package():
    return DNS(qr=0, qd=DNSQR()).build()


def is_dns_package(package):
    try:
        return DNS(_pkt=package).qr == 1
    except:
        return False


def build_pop3_packet():
    return str.encode("USER mrose")


def is_pop3_package(package):
    try:
        response = package.decode()
        return "+OK" in response or "-ERR" in response
    except:
        return False


def build_http_packet():
    return HTTPRequest().build()


def is_http_package(package):
    try:
        return HTTPResponse(_pkt=package).Status_Code != 0
    except:
        return False


def build_ntp_packet():
    return NTPHeader().build()


def is_ntp_package(package):
    try:
        return NTPHeader(_pkt=package).recv != 0
    except:
        return False


def build_smtp_packet():
    return str.encode("HELO relay.example.com")


def is_smtp_package(package):
    try:
        decoded = package.decode()
        return decoded[:3].isdigit()
    except:
        return False


if __name__ == '__main__':
    build_dns_package()
    pass
