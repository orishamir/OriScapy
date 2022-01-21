import socket
from Layer import Layer
from Tcp import TCP
from Udp import UDP
from HelperFuncs import *
from Icmp import ICMP
import conf
import struct

# RFC:
# https://datatracker.ietf.org/doc/html/rfc791#section-3.1
# https://en.wikipedia.org/wiki/IPv4#Packet_structure

# noinspection SpellCheckingInspection
class IP(Layer):
    _my__protocol = ProtocolTypes.IPv4
    ProtocolTypesIP_dict = Bidict(vars(ProtocolTypesIP))

    class Flags:
        DF = 0b0

    version       =  4            # IPv4
    IHL           =  None         # How long the IP header is (in 4 bytes, 5 means 20 bytes long and is the min)
    DSCP          =  0            # Something to do with Quality-Of-Service, Differentiated Services
    ECN           =  0            # Something to do with Quality-Of-Service, Differentiated Services
    total_length  =  None         # The total length header+data
    id            =  None         # The ID, just make it random (mostly I guess for fragmentation)
    flags         =  None         # dont fragment and more fragments and such
    frag_off      =  0            # This is for IP fragmentation, lets not worry about it rn lmao
    ttl           =  64           # everyone knows what time to live is stfu
    protocol      =  None         # Protocols include TCP (0x6), ICMP (0x1) and such.
    chksum        =  0            # stfu
    psrc          =  None         # ...
    pdst          =  None         # ...
    options       =  None         # stfu

    def __init__(self, *, src=None, dst=None, ttl=64, protocol=ProtocolTypesIP.ICMP, id=None):
        self.psrc      =  src
        self.pdst      =  dst
        self.ttl       =  ttl
        self.protocol  =  protocol
        self.id        =  id

        if not isIpv4(self.pdst):
            self.pdst = socket.gethostbyname(self.pdst)

    def __bytes__(self):
        self._autocomplete()
        if self.psrc is None:
            raise TypeError("Source IP not set")
        if self.pdst is None:
            raise TypeError("Destination IP not set")

        src_ip = ipv4ToBytes(self.psrc)
        dst_ip = ipv4ToBytes(self.pdst)
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
            tmp_pkt += struct.pack("!H", chksum16bit(tmp_pkt + src_ip + dst_ip))
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
            tmp_pkt += struct.pack("!H", chksum16bit(tmp_pkt + src_ip + dst_ip))
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

        if self.psrc is None:
            self.psrc = getIpAddr(conf.iface)

        try:
            self.protocol = self.data._my__protocol
        except AttributeError:
            self.protocol = ProtocolTypesIP.ICMP

        if self.pdst is None:
            print("Warning: Destination IP is automatically set to broadcast.")
            self.pdst = AddressesType.ipv4_broadcast

        self.chksum = 0

    def __str__(self):
        self.protocol = self.ProtocolTypesIP_dict.get(self.protocol, None)
        ret = super(IP, self).__str__()
        self.protocol = self.ProtocolTypesIP_dict.get(self.protocol, None)
        return ret
