import struct
import conf
from Icmp import ICMP
from Icmpv6 import ICMPv6
from Layer import Layer
from HelperFuncs import *

# IPv6 Pseudo Header:
# https://www.rfc-editor.org/rfc/rfc2460.html#section-8.1

# https://datatracker.ietf.org/doc/html/rfc2460#section-3
# https://en.wikipedia.org/wiki/IPv6_packet
class IPv6(Layer):
    _mac_dst_addr = "33:33:ff:7a:b3:24"

    version        = None  # Is 6
    traffic_class  = None  # Something with QoS?
    flow_label     = None
    payload_length = None  # Just data len
    protocol       = None  # RFC calls this "Next Header"...
    hoplimit       = None  # Literally the same as TTL
    psrc           = None
    pdst           = None

    def __init__(self, psrc=None, pdst=None, protocol=None, traffic_class=None, flow_label=None, hoplimit=None, ttl=None):
        self.traffic_class = traffic_class
        self.flow_label    = flow_label
        self.protocol      = protocol
        self.hoplimit      = hoplimit or ttl
        self.psrc          = psrc
        self.pdst          = pdst

    def __bytes__(self):
        self._autocomplete()

        if self.psrc is None:
            raise TypeError("Source IP not specified")
        if self.pdst is None:
            raise TypeError("Destination IP not specified")

        srcbytes = ipv6ToBytes(self.psrc)
        dstbytes = ipv6ToBytes(self.pdst)
        pkt = b''
        first_2_bytes = (self.version << 28) | (self.traffic_class << 20) | self.flow_label
        pkt += struct.pack("!L", first_2_bytes)
        pkt += struct.pack('!H', self.payload_length)
        pkt += struct.pack('!BB', self.protocol, self.hoplimit)
        pkt += srcbytes
        pkt += dstbytes
        if hasattr(self, 'data'):
            if isinstance(self.data, ICMPv6):
                pkt += self.data.toBytes(srcbytes, dstbytes)
            else:
                pkt += bytes(self.data)
        return pkt

    def _autocomplete(self):
        if self.version is None:
            self.version = 6

        if self.traffic_class is None:
            self.traffic_class = 0

        if self.flow_label is None:
            self.flow_label = 0

        if self.payload_length is None:
            if hasattr(self, "data"):
                self.payload_length = len(self.data)
            else:
                self.payload_length = 0

        if self.hoplimit is None:
            self.hoplimit = 64

        if self.psrc is None:
            self.psrc = getIpV6Addr(conf.iface)

        if self.pdst is None:
            try:
                self.pdst = self.data._ipdst__addr
            except AttributeError:
                pass

        try:
            self.protocol = self.data._my__protocol
        except AttributeError:
            self.protocol = ProtocolTypesIP.IPv6_NoNxt

# https://datatracker.ietf.org/doc/html/rfc2460#section-4.2
class ExtensionHeader:
    type   = None  # First 2 bits specify the action that must be taken if the processing
                   # IPv6 node does not recognize the Option Type:
    length = None
    data   = None

    def __init__(self, type=None, length=None, data=None):
        self.type = type
        self.length = length
        self.data = data

        raise NotImplementedError
