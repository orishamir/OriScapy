import HelperFuncs
import Sendreceive
from Arp import ARP
from Dns import DNS, DNSQR, DNSRR
from Ethernet import Ether
from Ip import IP
from Raw import Raw
from Udp import UDP
from Tcp import TCP
from Icmp import ICMP

# https://en.wikipedia.org/wiki/List_of_RFCs

def bytes2bitsPadded(bts):
    return [f"{bin(bt)[2:]:0>8}" for bt in bts]

def resolve_mac(ip):
    pkt = Ether()/ARP(dst_ip=ip)
    return Sendreceive.sendreceive(pkt)[ARP].sender_mac

if __name__ == '__main__':
    pkt = Ether()/IP(dst="192.168.1.255")/ICMP()
    print(Sendreceive.sendreceive(pkt, flipIP=False))
