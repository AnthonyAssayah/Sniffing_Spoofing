from scapy.all import *

a = IP()
a.src = '10.0.2.6'
a.dst = '8.8.8.8'
b = ICMP()
p = a/b
send(p)
ls(a)
