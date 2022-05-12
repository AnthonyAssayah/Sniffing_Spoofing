#!/usr/bin/env python3

from scapy.all import *

a = IP()
a.dst = "129.134.31.12"

class success():
    x = 0

def print_pkt(pkt):
    if pkt[IP].src == "129.134.31.12":
        #pkt.show()
        success.x = 1

for i in range(1,50):
    a.ttl = i
    b = ICMP()
    p = a/b
    send(p)
    pkt = sniff(filter="icmp",timeout = 0.5, prn=print_pkt)
    if success.x == 1:
        print("TRACEROUTE ---> " ,str(i))
        break
