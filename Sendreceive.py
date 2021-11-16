import socket
import struct
from Arp import ARP
from Dns import DNS, DNSQR, DNSRR, QTYPES
from Ethernet import Ether
from Icmp import ICMP
from Ip import IP
from Raw import Raw
from Tcp import TCP
from Udp import UDP
from conf import iface
from Values import ProtocolTypes, bytesToMac, bytesToIpv4
# https://stackoverflow.com/a/57133488/9100289

ETH_P_ALL = 3 # not defined in socket module, sadly...
recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
recv_sock.bind((iface, 0))

send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
send_sock.bind((iface, 0))

ethernetLen = 6+6+2
arpLen      = 2+2+1+1+2+6+4+6+4
ipLen       = 2+2+2+2+2+2+4+4
udpLen      = 2+2+2+2
icmpLen     = 1+1+2+2+2
dnsLen      = 2+2+2+2+2+2

def parseUDP(data, pkt):
    src_port, dst_port, length, udp_chksum = struct.unpack('!HHHH', data[:8])
    pkt /= UDP(sport=src_port, dport=dst_port)
    return parseData(data[udpLen:], pkt)

def parseICMP(data, pkt):
    type, code, icmpChecksum, id, seq = struct.unpack('!BBHHH', data[:8])
    pkt /= ICMP(type_=type, code=code, id=id, seq=seq)

    data = data[icmpLen:]
    if data == b'':
        return pkt
    return parseData(data, pkt)

def parseIP(data, pkt):
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0b00001111

    data = data[1:]
    tos, total_len, id, flags_fragoffset, ttl, prot, chksum, src, dst = struct.unpack('!B H H H B B H 4s 4s',
                                                                                      data[:ihl * 4 - 1])
    src = bytesToIpv4(src)
    dst = bytesToIpv4(dst)
    data = data[ihl * 4 - 1:]

    # print(data)
    # print(hex(version), hex(ihl), hex(tos), hex(total_len), hex(id), flags_fragoffset, ttl, prot, chksum, src, dst)

    pkt /= IP(src=src, dst=dst, ttl=ttl, protocol=prot, id=id)
    if prot == IP.ProtocolTypesIP.ICMP:
        # print("This is an ICMP packet")
        pkt = parseICMP(data, pkt)
        return pkt
    elif prot == IP.ProtocolTypesIP.UDP:
        # print("This is a UDP packet")
        pkt = parseUDP(data, pkt)

        # Here comes the hard part, trying to figure out exactly what type
        # of UDP data was sent. Some possibilities are:
        # UDP, DHCP, Literally any Streaming Services, NTP, or
        # some random 5 year old that opened a UDP socket using Python.

        # This means i'll do it later and not rn :)
    else:
        pkt = parseData(data, pkt)
    return pkt

def parseEther(data):
    # Parse Ethernet
    eth = data[:ethernetLen]
    dst, src, type = struct.unpack('!6s6sH', eth)
    dst = bytesToMac(dst)
    src = bytesToMac(src)
    fcs = data[-4:]
    data = data[ethernetLen:]
    pkt = Ether(dst=dst, src=src, ethType=type)
    # print("Ethernet data:", dst, src, type)
    if type == ProtocolTypes.ARP:
        # Parse arp
        arp = data[:arpLen]
        hwtype, ptype, hwlen, plen, op, hwsrc, psrc, hwdst, pdst = struct.unpack('!H H B B H 6s 4s 6s 4s', arp)

        hwsrc = bytesToMac(hwsrc)
        hwdst = bytesToMac(hwdst)
        psrc  = bytesToIpv4(psrc)
        pdst  = bytesToIpv4(pdst)

        # print(hex(hwtype), hex(ptype), hex(hwlen), hex(plen), hex(op), hwsrc, psrc, hwdst, pdst)
        # print(dst, src, hex(type))
        return pkt/ARP(hwtype=hwtype, ptype=ptype, opcode=op, dst_ip=pdst, dst_mac=hwdst, src_ip=psrc, src_mac=hwsrc,psize=plen, hwsize=hwlen)
    elif type == ProtocolTypes.IPv4:
        # print("An IP packet")
        pkt = parseIP(data, pkt)

    return pkt

def parseData(data, pkt):
    if UDP in pkt:
        if 53 in (pkt[UDP].dport, pkt[UDP].sport) or 5353 in (pkt[UDP].dport, pkt[UDP].sport):
            return pkt/parseDNS(data)
        elif 67 in (pkt[UDP].dport, pkt[UDP].sport):
            # DHCP
            pass
    return pkt/Raw(load=data)

def parseDNS(data):
    def parseName(dta):
        qname = ''
        tmp = list(dta[:dta.index(b'\x00') + 1])
        while tmp:
            if tmp[0] == '\x00':
                break
            for _ in range(tmp.pop(0)):
                qname += chr(tmp.pop(0))
            qname += '.'
        qname = qname.strip('.')
        return qname

    copydata = data
    id, tmp, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:dnsLen])

    QR     = tmp >> 15
    opcode = (tmp >> 11) & 0b1111
    AA     = (tmp >> 10) & 0b1
    TC     = (tmp >> 9) & 0b1
    RD     = (tmp >> 8) & 0b1
    RA     = (tmp >> 7) & 0b1
    Z      = (tmp >> 4) & 0b111
    rcode  = tmp & 0b1111

    data = data[dnsLen:]
    if len(data) == 0:
        return DNS(rd=RD, ra=RA, id=id, rcode=rcode, opcode=opcode, qr=QR,
                   qdcount=qdcount, ancount=ancount, nscount=nscount, arcount=arcount)

    qd = []
    an = []
    for section in ['qd', 'an']:
        count = locals()[section+"count"]
        if count == 0:
            continue
        for _ in range(count):
            if section == 'qd':
                qname = parseName(data)
                data = data[data.index(b'\x00')+1:]
                qtype, qclass = struct.unpack('!HH', data[:4])
                data = data[4:]
                qd.append(DNSQR(qname=qname, qtype=qtype, qclass=qclass))
            elif section == 'an':
                #  may be a pointer to the name (offset from DNS header start), or just a name.
                if (data[0] >> 6) == 0b11:
                    # is pointer.
                    pointerVal = ((data[0] << 8) | data[1]) & 0b0011111111111111
                    rname = parseName(copydata[pointerVal:])
                    data = data[2:]
                else:
                    rname = parseName(data[:data.index(b'\x00')+1])
                    data = data[data.index(b'\x00') + 1:]

                rtype, rclass, ttl, rdlen = struct.unpack('!HHLH', data[:10])
                data = data[10:]
                rdata = data[:rdlen]
                if rtype == QTYPES.A:
                    rdata = bytesToIpv4(rdata)
                elif rtype == QTYPES.AAAA:
                    # rdata = bytesToIpv6()
                    pass
                data = data[rdlen:]
                an.append(DNSRR(name=rname, type=rtype, class_=rclass & 0b011111111111111, ttl=ttl, rdata=rdata))

    pkt = DNS(rd=RD, ra=RA, id=id, rcode=rcode, opcode=opcode, qr=QR,
               qdcount=qdcount, ancount=ancount, nscount=nscount, arcount=arcount,
               qd=qd, an=an)
    if data:
        pkt = pkt/Raw(load=data)
    return pkt

def send(pkt: Ether):
    assert isinstance(pkt, Ether), 'pkt must be of type Ethernet to be sent.'
    send_sock.send(pkt.__bytes__()[0])

def is_response(res, pkt):
    # Check if the layers are not the same.
    if ((IP in res) != (IP in pkt)) or ((UDP in res) != (UDP in pkt)) or ((ICMP in res) != (ICMP in pkt))\
        or ((ARP in res) != (ARP in pkt)):
        return False

    if IP in pkt:
        # dst and src ip should have been switched.
        if not (res[IP].dst_ip == pkt[IP].src_ip and res[IP].src_ip == pkt[IP].dst_ip):
            return False
        if ICMP in res and ICMP in pkt:
            return res[ICMP].id == pkt[ICMP].id and res[ICMP].seq == pkt[ICMP].seq

        if UDP in pkt:
            # dport and sport should have been switched
            if not (res[UDP].dport == pkt[UDP].sport and res[UDP].sport == pkt[UDP].dport):
                return False
            return True
    elif ARP in pkt:
        resarp: ARP = res[ARP]
        pktarp: ARP = pkt[ARP]
        return resarp.target_ip == pktarp.sender_ip and resarp.hwsize == pktarp.hwsize and resarp.opcode != pktarp.opcode

def sendreceive(pkt: Ether):
    send(pkt)
    while True:
        res = recv_sock.recvfrom(1500)[0]
        try:
            res = parseEther(res)
        except (ValueError, struct.error):
            continue
        if res is None:
            continue
        if is_response(res, pkt):
            return res

print(parseEther(b"\x01\x00\x5e\x00\x00\xfb\x9c\xeb\xe8\xb3\xb4\x47\x08\x00\x45\x00" \
b"\x00\x4d\x1a\x4d\x40\x00\xff\x11\xbe\xa4\xc0\xa8\x01\x0a\xe0\x00" \
b"\x00\xfb\x14\xe9\x14\xe9\x00\x39\x8b\x33\x00\x00\x84\x00\x00\x00" \
b"\x00\x01\x00\x00\x00\x00\x0f\x6d\x69\x6c\x69\x6e\x6b\x34\x31\x32" \
b"\x30\x30\x37\x39\x36\x31\x05\x6c\x6f\x63\x61\x6c\x00\x00\x01\x80" \
b"\x01\x00\x00\x00\x78\x00\x04\xc0\xa8\x01\x0a"
))