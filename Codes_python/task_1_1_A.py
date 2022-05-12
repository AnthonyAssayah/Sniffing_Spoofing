#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
	pkt.show()
	
pkt = sniff(iface=['br-6a709a0e8789', 'enp0s3'], filter='icmp', prn=print_pkt)
