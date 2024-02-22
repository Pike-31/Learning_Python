#!/usr/bin/python3

import subprocess
import optparse
import re


def getArgs():
    parser = optparse.OptionParser()
    parser.add_option(
        "-i", "--interface", dest="interface", help="Interface to change MAC address."
    )
    parser.add_option(
        "-m", "--mac", dest="mac", help="Destination MAC address for interface."
    )
    (options, arguments) = parser.parse_args()
    if not options.interface:
        # code to handle error
        parser.error("[-] An interface must be specified with -i or --interface.")
    elif not options.mac:
        # code to handle error
        parser.error("[-] A mac must be specified with -m or --mac.")
    return options


def changeMac(interface, mac):
    subprocess.call(["sudo", "ip", "link", "set", interface, "down"])
    subprocess.call(["sudo", "ip", "link", "set", interface, "address", mac])
    subprocess.call(["sudo", "ip", "link", "set", interface, "up"])
    print("Changing", interface, "MAC to", mac)


def findCurrentMac(interface):
    ip_a_result = subprocess.check_output(["ip", "a", "show", "dev", interface])
    mac_result = re.search(r"(\w\w:){5}\w\w", str(ip_a_result))
    if mac_result:
        return mac_result.group(0)
    else:
        print("[-] Could not find MAC assigned to interface", interface)


def validateMacChange(interface, mac):
    current_mac_2 = findCurrentMac(interface)
    if current_mac_2 != mac:
        print("[+] MAC on", interface, "was successfully changed to", current_mac_2)
    else:
        print("[-] MAC on", interface, "was NOT changed.")


options = getArgs()
current_mac = findCurrentMac(options.interface)
print("Current MAC:", str(current_mac))
changeMac(options.interface, options.mac)
validateMacChange(options.interface, current_mac)
