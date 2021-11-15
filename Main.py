from __future__ import annotations
from Arp import ARP
from Dns import DNS, DNSQR, DNSRR
from Ethernet import Ether
from Ip import IP
from Udp import UDP
from Tcp import TCP
from Icmp import ICMP

# s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
# s.bind((iface, 0))

# https://en.wikipedia.org/wiki/List_of_RFCs

def bytes2bitsPadded(bts):
    return [f"{bin(bt)[2:]:0>8}" for bt in bts]

if __name__ == '__main__':
    #pkt = Ether(dst="98:1e:19:7a:b3:24")/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR("facebook.com"), an=DNSRR(name='google.com', rdata='192.168.1.1'))
    #pkt = Ether(dst="98:1e:19:7a:b3:24")/IP(dst="192.168.1.1")/TCP(dport=80, sport=20)
    #print(pkt.data.data.__bytes__())
    #print(pkt.__bytes__())
    pkt = DNS(qd=DNSQR("facebook.com"))
    print(pkt.__bytes__())
    #pkt = Ether(dst="98:1e:19:7a:b3:24")/IP(dst='192.168.1.2')/ICMP()
    #print(pkt)
    #print(pkt.__bytes__())
    #pkt = Ether(dst="98:1e:19:7a:b3:24")/IP(dst="8.8.8.8")/TCP()

