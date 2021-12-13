from All import *

# Resolve google.com by querying google's DNS server (8.8.8.8)
pkt = Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="google.com"))
res = sendreceive(pkt)

for answer_record in res.an:
	print(answer_record.rdata)