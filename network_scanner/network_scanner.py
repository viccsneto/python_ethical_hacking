#!/usr/bin/env python3

import scapy.all as scapy
import optparse

scapy.conf.verb = False

parser = optparse.OptionParser()
parser.add_option("-t", "--target", dest="target", help="Target IP / IP Range.")

def get_arguments():
    options, arguments = parser.parse_args()
    return options

def scan(target):
    arp_request = scapy.ARP(pdst=target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]
    print("------------------------------------")
    print("IP\t\tMAC")
    print("------------------------------------")
    for element in answered_list:
        print(element[1].psrc +"\t"+ element[1].hwsrc)
    
    print("------------------------------------")

options = get_arguments() 

if (options.target is None):
    parser.print_usage()
    parser.print_help()
    exit(1)

scan(options.target)
