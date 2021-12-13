
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

All those fields are automatically completed by Scapy for your own comfort,   
Scapy automatically detects the type of packet to be sent is ARP,  
And so it sets the `type` field to `0x806 (ARP)`, like it should be.   
Also, the `Source MAC` and the `Destination MAC` are automatically detected and filled.

And so I wanted for my knowledge about Networking, to learn more about  
the most famous packets' header format.   
And to do that I thought to make my own Scapy which would support    
Ethernet, ARP, IP, ICMP, UDP, DNS and maybe more in the future.

## Usage
First of all, don't. Please just use [Scapy](https://pypi.org/project/scapy/).   
But if you insist, then its basically the same as Scapy. Here are some examples:    

#### ARP Queries
```python
from All import *

ip = "192.168.1.2"
# Resolve 192.168.1.2's MAC Address
pkt = Ether()/ARP(pdst=ip)  # Everything is auto-completed :)
res = sendreceive(pkt)
print(f"{ip}'s MAC address is {res.sender_mac}")
```
#### DNS Queries
(No support for Additional and Authorative RRs)
```python
from All import *  
  
# Resolve google.com by quering google's DNS server (8.8.8.8)  
pkt = Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="google.com"))  
res = sendreceive(pkt, timeout=3)

for answer_record in res.an:
	print(answer_record.rdata)
```

#### Ping an IP
```python
from All import *

# Ping google's DNS server
pkt = Ether()/IP(dst="8.8.8.8")/ICMP()
res = sendreceive(pkt, timeout=2)
print(res)
```

#### ARP Spoofing/Cache Poisoning
```python
from All import *
# Example TBC
```

#### DNS Amplification
```python
from All import *
# Example TBC
```
    

#### DNS Cache Poisoning
```python
from All import *
# Example TBC
```
