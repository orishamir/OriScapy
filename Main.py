from All import *

pkt = Ether()/IP(dst="8.8.8.8")/ICMP()
print(pkt)
print(sr(pkt))
