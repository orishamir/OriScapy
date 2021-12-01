import socket

from Layer import Layer
from Tcp import TCP
from Udp import UDP
from HelperFuncs import *
from Icmp import ICMP
from conf import iface
import struct

# RFC:
# https://datatracker.ietf.org/doc/html/rfc791#section-3.1
# https://en.wikipedia.org/wiki/IPv4#Packet_structure

# IPv4 protocol nums: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers

# noinspection SpellCheckingInspection
class IP(Layer):
    class ProtocolTypesIP:
        ICMP      = 0x1
        TCP       = 0x6
        UDP       = 0x11
        IPv6      = 0x29

    ProtocolTypesIP_dict = Bidict(vars(ProtocolTypesIP))

    class Flags:
        DF = 0b0

    version          =  4            # IPv4
    IHL              =  None         # How long the IP header is (in 4 bytes, 5 means 20 bytes long and is the min)
    DSCP             =  0            # I dont fucking know
    ECN              =  0            # I dont fucking know
    total_length     =  None         # The total length header+data
    id               =  None         # The ID, just make it random lmfao (fragmentation soon...)
    flags            =  None         # dont fragment and more fragments and such
    frag_off         =  0            # This is for IP fragmentation, lets not worry about it rn lmao
    ttl              =  64           # everyone knows what time to live is stfu
    protocol         =  None         # Protocols include TCP (0x6), ICMP (0x1) and such.
    chksum           =  0            # stfu
    src_ip           =  None         # ...
    dst_ip           =  None         # ...
    options          =  None         # stfu

    def __init__(self, *, src=None, dst=None, ttl=64, protocol=ProtocolTypesIP.ICMP, id=None):
        self.src_ip         =  src
        self.dst_ip         =  dst
        self.ttl            =  ttl
        self.protocol       =  protocol
        self.id             =  id

        if not isIpv4(self.dst_ip):
            self.dst_ip = socket.gethostbyname(self.dst_ip)

    def __bytes__(self):
        self._autocomplete()

        src_ip = ipv4ToBytes(self.src_ip)
        dst_ip = ipv4ToBytes(self.dst_ip)
        # fucking version and IHL are 4 bits each
        first2Bytes = struct.pack("B", (self.version << 4) | self.IHL)
        first2Bytes += struct.pack("B", (self.DSCP << 2)  | self.ECN)

        if not hasattr(self, 'data'):
            print("Warning: No data inside IP packet.")
            tmp_pkt = first2Bytes
            tmp_pkt += struct.pack("!H", self.IHL * 4)
            tmp_pkt += struct.pack("!H", self.id)
            tmp_pkt += struct.pack("!H", 0)
            tmp_pkt += struct.pack("!B", self.ttl)
            tmp_pkt += struct.pack("!B", self.protocol)
            tmp_pkt += struct.pack("!H", checksum(tmp_pkt + src_ip + dst_ip))
            tmp_pkt += src_ip
            tmp_pkt += dst_ip
            return tmp_pkt

        # IP fragmentation... very fun
        all_bytes = bytes(self.data)
        frags_bytes = []

        for i in range(len(all_bytes)//1480+1):
            frags_bytes.append(all_bytes[i*1480:1480*(i + 1)])

        pkt_frags = []
        for i in range(len(frags_bytes)):
            frag_bytes = frags_bytes[i]
            flags = 0b000 if i == len(frags_bytes)-1 else 0b001
            offset = i*1480

            tmp_pkt = first2Bytes
            tmp_pkt += struct.pack("!H", self.IHL*4+len(frag_bytes))
            tmp_pkt += struct.pack("!H", self.id)
            tmp_pkt += struct.pack("!H", (flags << 13) | offset)
            tmp_pkt += struct.pack("!B", self.ttl)
            tmp_pkt += struct.pack("!B", self.protocol)
            tmp_pkt += struct.pack("!H", checksum(tmp_pkt+src_ip+dst_ip))
            tmp_pkt += src_ip
            tmp_pkt += dst_ip

            tmp_pkt += frag_bytes

            pkt_frags.append(tmp_pkt)

        return pkt_frags

    def _autocomplete(self):
        if self.IHL is None:
            # depending on options, set the IHL value accordingly
            self.IHL = 5

        if self.id is None:
            self.id = RandShort()

        if self.src_ip is None:
            self.src_ip = getIpAddr(iface)

        if not hasattr(self, 'data'):
            self.protocol = self.ProtocolTypesIP.ICMP
        elif isinstance(self.data, ICMP):
            self.protocol = self.ProtocolTypesIP.ICMP
        elif isinstance(self.data, TCP):
            self.protocol = self.ProtocolTypesIP.TCP
        elif isinstance(self.data, UDP):
            self.protocol = self.ProtocolTypesIP.UDP

        if self.dst_ip is None:
            print("Warning: Destination IP is automatically set to broadcast.")
            self.dst_ip = AddressesType.ipv4_broadcast

        self.chksum = 0

    def __str__(self):
        self.protocol = self.ProtocolTypesIP_dict[self.protocol]
        ret = super(IP, self).__str__()
        self.protocol = self.ProtocolTypesIP_dict[self.protocol]
        return ret
