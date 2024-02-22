#!/usr/bin/python3

import scapy.all as scapy
import argparse


def parseArgs():
    parser = argparse.ArgumentParser(
        description="This is a simple network scanner that works by sending ARP requests to the layer 2 broadcast address."
    )
    parser.add_argument(
        "-t", "--target", dest="target", help="Target IP or network/# to scan"
    )
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Target IP or network must be set with -t or --target")
    return options


def arpScan(ip):
    arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    arp_request_packet = broadcast / arp
    answered_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]
    client_list_dict = []
    for response in answered_list:
        client_dict = {"ip": response[1].psrc, "mac": response[1].hwsrc}
        client_list_dict.append(client_dict)
    return client_list_dict


def printResult(result_list):
    print("------------------------------------------")
    print("IP\t\t\tMAC")
    print("------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = parseArgs()
clients = arpScan(options.target)
results = printResult(clients)
