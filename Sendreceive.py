import socket
import struct

import netifaces

from HelperFuncs import ProtocolTypes, bytesToMac, bytesToIpv4, ProtocolTypesIP, bytesToIpv6
from Dns import DNS, DNSQR, DNSRR, QTYPES
from Ethernet import Ether
from Icmp import ICMP
from Ipv6 import IPv6
from Raw import Raw
from Arp import ARP
from Udp import UDP
from Tcp import TCP
from Ip import IP
import conf
import time

LINUX = __import__("os").name.lower() == "posix"

if LINUX:
    def prepareSockets(iface):
        # https://stackoverflow.com/a/57133488/9100289
        global recv_sock
        global send_sock

        ETH_P_ALL = 3  # not defined in socket module, sadly...
        recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        recv_sock.bind((conf.iface, 0))

        send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        send_sock.bind((conf.iface, 0))

        conf.iface = iface
else:
    from winpcapy import WinPcapDevices, WinPcap
    PREFIX = "\\Device\\NPF_"

    def prepareSockets(iface=None):
        global send_sock
        try:
            # check if iface exists
            netifaces.ifaddresses(iface)
        except (ValueError, TypeError):
            # if not, find the first available interface
            name, desc = WinPcapDevices.get_matching_device("*")
            iface = name.split("_")[1]

        conf.iface = iface
        send_sock = WinPcap(PREFIX + iface, conf.iface)

prepareSockets(conf.iface)

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

    pkt /= IP(psrc=src, pdst=dst, ttl=ttl, protocol=prot, id=id)
    if prot == ProtocolTypesIP.ICMP:
        # print("This is an ICMP packet")
        pkt = parseICMP(data, pkt)
        return pkt
    elif prot == ProtocolTypesIP.UDP:
        # print("This is a UDP packet")
        pkt = parseUDP(data, pkt)

        # Here comes the hard part, trying to figure out exactly what type
        # of UDP data was sent. Some possibilities are:
        # UDP, DHCP, Literally any Streaming Service, NTP, or
        # some random 5 year old that opened a UDP socket using Python.

        # This means i'll do it later and not rn :)
        # Except DNS, which I implemented.
    else:
        pkt = parseData(data, pkt)
    return pkt

def parseIPv6(data, pkt):
    version_trafficClass_flowLabel, payload_len, next_header, hoplimit, src, dst= struct.unpack("!LHBB 16s 16s", data[:40])

    version = version_trafficClass_flowLabel >> 28

    traffic_class = (version_trafficClass_flowLabel >> 20) & 0xFF
    flow_label = version_trafficClass_flowLabel & 0xFFFFF

    # print(src)
    pkt /= IPv6(psrc=bytesToIpv6(src), pdst=bytesToIpv6(dst), ttl=hoplimit, traffic_class=traffic_class,
                flow_label=flow_label, nextheader=next_header)

    if next_header == ProtocolTypesIP.UDP:
        pkt = parseUDP(data[40:], pkt)
    elif next_header == ProtocolTypesIP.ICMP:
        pkt = parseICMP(data[40:], pkt)
    else:
        pkt = parseData(data[40:], pkt)
    return pkt

def parseEther(data):
    # In retrospect, I should have made this a classmethod inside the Ether class, oh well.
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
        return pkt/ARP(hwtype=hwtype, ptype=ptype, opcode=op, pdst=pdst, hwdst=hwdst, psrc=psrc, hwsrc=hwsrc, psize=plen, hwsize=hwlen)
    elif type == ProtocolTypes.IPv4:
        # print("An IP packet")
        pkt = parseIP(data, pkt)
    elif type == ProtocolTypes.IPv6:
        pkt = parseIPv6(data, pkt)
    return pkt

def parseData(data, pkt):
    if UDP in pkt:
        if 53 in (pkt[UDP].dport, pkt[UDP].sport) or 5353 in (pkt[UDP].dport, pkt[UDP].sport) or 5355 in (pkt[UDP].dport, pkt[UDP].sport):
            return pkt/parseDNS(data)
        elif 67 in (pkt[UDP].dport, pkt[UDP].sport):
            # DHCP
            pass
    return pkt/Raw(load=data)

def parseDNS(data):
    def parseName(dta):
        # A name can be a pointer to a previous name, or just a regular string
        # (https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4)
        # Its a pointer iff the first 2 bits are 1. if its a pointer then the
        # "address" the pointer to pointing to is the rest of the 8 bit number.
        # Otherwise, its a string. The name is represented as a sequence of labels, where
        #                 each label consists of a length octet followed by that
        #                 number of octets. The domain name terminates with the
        #                 zero length octet for the null label of the root.  Note
        #                 that this field may be an odd number of octets; no
        #                 padding is used.
        # Example:  www.google.com=\x03www\x06google\x03com\x00
        # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
        if (dta[0] >> 6) == 0b11:
            # is pointer.
            pointerVal = ((dta[0] << 8) | dta[1]) & 0b0011111111111111
            return parseName(copydata[pointerVal:])

        size = 0
        name = ''
        tmp = list(dta)
        while tmp:
            if tmp[0] == 0:
                break
            size += 1
            a = tmp.pop(0)
            for _ in range(a):
                name += chr(tmp.pop(0))
                size += 1
            name += '.'
            if tmp and (tmp[0] >> 6) == 0b11:
                return name+parseName(dta[size:])
        name = name.strip('.')
        return name

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
                   qdcount=qdcount, ancount=ancount, nscount=nscount, arcount=arcount, aa=AA)

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
                # may be a pointer to the name (offset from DNS header start), or just a name.
                rname = parseName(data)
                data = data[data.index(b'\x00'):]

                rtype, rclass, ttl, rdlen = struct.unpack('!HHLH', data[:10])
                data = data[10:]
                rdata = data[:rdlen]
                if rtype == QTYPES.A:
                    rdata = bytesToIpv4(rdata)
                elif rtype == QTYPES.AAAA:
                    # rdata = bytesToIpv6()
                    pass
                data = data[rdlen:]
                an.append(DNSRR(name=rname, type=rtype, rclass=rclass & 0b011111111111111, ttl=ttl, rdata=rdata))

    pkt = DNS(rd=RD, ra=RA, id=id, rcode=rcode, opcode=opcode, qr=QR,
               qdcount=qdcount, ancount=ancount, nscount=nscount, arcount=arcount,
               qd=qd, an=an, aa=AA)
    if data:
        pkt = pkt/Raw(load=data)
    return pkt


def send(pkt: Ether, count=1, interval=0, verbose=False):
    assert isinstance(pkt, Ether), 'pkt must be of type Ethernet to be sent.'
    bts = pkt.__bytes__()
    assert len(bts) == 1, "Does not support sending fragmented packets as of now."

    for _ in range(count):
        if LINUX:
            send_sock.send(bts[0])
        else:
            with WinPcap(PREFIX + conf.iface) as ss:
                ss.send(bts[0])
        if verbose:
            print(". ", end="")
        time.sleep(interval)
    if verbose:
        print()

def _is_response(res, pkt, *, flipIP, flipMAC, flipPort):
    # Check if the layers are not the same.
    if ((IP in res) != (IP in pkt)) or ((UDP in res) != (UDP in pkt)) or ((ICMP in res) != (ICMP in pkt))\
        or ((ARP in res) != (ARP in pkt)):
        return False

    if flipMAC and not (res.dst == pkt.src and res.src == pkt.dst):
        return False

    if IP in pkt:
        pktIP: IP = pkt[IP]
        resIP: IP = res[IP]

        # plz res != pkt
        if pktIP.pdst == resIP.pdst and pktIP.psrc == resIP.psrc:
            return False
        # dst and src ip should have been switched. (if flipIP is True)
        if flipIP and not (resIP.pdst == pktIP.psrc and resIP.psrc == pktIP.pdst):
            return False
        if ICMP in pkt:
            return res[ICMP].id == pkt[ICMP].id and res[ICMP].seq == pkt[ICMP].seq

        if UDP in pkt:
            # dport and sport should have been switched (maybe)
            if flipPort and not (res[UDP].dport == pkt[UDP].sport and res[UDP].sport == pkt[UDP].dport):
                return False
            return True
    elif ARP in pkt:
        resarp: ARP = res[ARP]
        pktarp: ARP = pkt[ARP]
        return resarp.pdst == pktarp.psrc and resarp.opcode != pktarp.opcode

if LINUX:
    def sendreceive(pkt: Ether, flipIP=True, flipMAC=False, flipPort=True, timeout=5):
        assert LINUX, "sendreceive is only supported on Linux currently."
        send(pkt)
        st = time.time()
        while True:
            res = recv_sock.recvfrom(1500)[0]
            try:
                res = parseEther(res)
            except (ValueError, struct.error, IndexError):
                continue
            if res is None:
                continue
            if _is_response(res, pkt, flipIP=flipIP, flipMAC=flipMAC, flipPort=flipPort):
                return res
            if time.time()-st > timeout:
                raise TimeoutError("sendreceive() timed out when sending packet", repr(pkt), '\nHas timed out')
else:
    def sendreceive(pkt: Ether, flipIP=True, flipMAC=False, flipPort=True, timeout=5):
        send(pkt)
        st = time.time()

        # with WinPcap(PREFIX + conf.iface) as recv_sock:
            # recv_sock.run(callback=lambda *_, pktbytes: )

def sniff(ismatch, onmatch, exitAfterFirstMatch=False, timeout=None):
    """
    :param ismatch: The function to check if a packet is a match
    :param onmatch: The function to call when a matched packet is found
    :param exitAfterFirstMatch: Should the function exist after the first match
    :param timeout:
    :return:
    """
    st = time.time()
    while True:
        res = recv_sock.recvfrom(1500)[0]
        try:
            res = parseEther(res)
        except (ValueError, struct.error, IndexError):
            continue
        if res is None:
            continue
        if ismatch(res):
            onmatch(res)
            if exitAfterFirstMatch:
                return
        if timeout and time.time() - st > timeout:
            raise TimeoutError("Sniff function timed out")  # Should this be an error?
