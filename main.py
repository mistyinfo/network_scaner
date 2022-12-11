# import os
# os.sys.path.append('/Library/Frameworks/Python.framework/Versions/3.10/bin/scapy')
from scapy.all import *
import scapy.all as scapy
import argparse


def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target',dest='target',help='Target IP/IP range.')
    options = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Широковещательный запрос
    arp_request_broadcast = broadcast/arp_request # Формирование пакета
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict ={"ip": element[1].psrc,"mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_argument()
scan_result = scan(options.target)
print(print_result(scan_result))

