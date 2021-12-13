from All import *

# https://en.wikipedia.org/wiki/List_of_RFCs

def bytes2bitsPadded(bts):
    return [f"{bin(bt)[2:]:0>8}" for bt in bts]

def resolve_mac(ip):
    pkt = Ether()/ARP(pdst=ip)
    return sendreceive(pkt)[ARP].sender_mac

if __name__ == '__main__':
    # pkt = Ether()/IP(dst="192.168.1.255")/ICMP()
    # print(Sendreceive.sendreceive(pkt, flipIP=False))
    # pkt = Ether()/IP(dst="8.8.8.8")/ICMP()
    # print(sendreceive(pkt))
    pkt = Ether()/ARP(pdst="192.168.1.2")
    print(sendreceive(pkt))
