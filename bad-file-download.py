#!/usr/bin/python3

import netfilterqueue
import scapy.all as scapy
from icecream import ic


def createForwardQueue():
    subprocess.run(
        ["sudo", "iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"]
    )


def removeForwardQueue():
    subprocess.run(
        ["sudo", "iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"]
    )


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            ic("HTTP Request:")
            ic(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            ic("HTTP Response:")
            ic(scapy_packet.show())


    packet.accept()



queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
