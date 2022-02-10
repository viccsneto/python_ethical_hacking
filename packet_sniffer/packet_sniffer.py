#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import optparse

scapy.conf.verb = False

parser = optparse.OptionParser()
parser.add_option("-i", "--interface", dest="interface", help="Network Interface Name")
parser.add_option("-f", "--filter", dest="filter", help="Sniffing Filter")
parser.add_option("-H", "--http", dest="http", action="store_true", default=False, help="HTTP Traffic Only")

def get_arguments():
    options, arguments = parser.parse_args()
    return options

options = get_arguments()

if (options.interface is None):
    parser.print_usage()
    parser.print_help()
    exit(1)

def sniff(interface, filter):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter=filter)

def process_sniffed_packet(packet):
    accept = True

    if options.http:
        accept = packet.haslayer(http.HTTPRequest) or packet.haslayer(http.HTTPResponse)
    
    if accept:
        print(packet.show())

sniff(options.interface, options.filter)
