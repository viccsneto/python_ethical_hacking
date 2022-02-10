#!/usr/bin/env python3
import subprocess
import netfilterqueue
import sys
import optparse

DEFAULT_QUEUE_NUM = 0
exit_code = 0
dropped_packet_count = 0

parser = optparse.OptionParser()
parser.add_option("-q", "--queue-num", dest="queue_num", default=DEFAULT_QUEUE_NUM, help="IPTables Queue Num")
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

def drop_packet(packet):
    global dropped_packet_count 
    dropped_packet_count += 1
    print("\r[+] Dropped packets: " + str(dropped_packet_count), end="")
    packet.drop()

def run_netfilter(queue_num):
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(queue_num, drop_packet)
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