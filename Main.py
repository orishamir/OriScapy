from Sendreceive import sendreceive
from Ethernet import Ether
from Ip import IP
from Icmp import ICMP
from Arp import ARP
import HelperFuncs
from Dns import DNS, DNSQR, DNSRR
from Raw import Raw
from Udp import UDP
from Tcp import TCP

# https://en.wikipedia.org/wiki/List_of_RFCs

def bytes2bitsPadded(bts):
    return [f"{bin(bt)[2:]:0>8}" for bt in bts]

def resolve_mac(ip):
    pkt = Ether()/ARP(dst_ip=ip)
    return sendreceive(pkt)[ARP].sender_mac

if __name__ == '__main__':
    # pkt = Ether()/IP(dst="192.168.1.255")/ICMP()
    # print(Sendreceive.sendreceive(pkt, flipIP=False))
    pkt = Ether()/IP(dst="8.8.8.8")/ICMP()
    print(sendreceive(pkt))
