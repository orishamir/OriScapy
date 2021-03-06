import struct
import conf
from Icmp import ICMP
from Icmpv6 import ICMPv6
from Layer import Layer
from HelperFuncs import *
from abc import ABCMeta, abstractmethod
# IPv6 Pseudo Header:
# https://www.rfc-editor.org/rfc/rfc2460.html#section-8.1

# https://datatracker.ietf.org/doc/html/rfc2460#section-3
# https://en.wikipedia.org/wiki/IPv6_packet
from Udp import UDP


class IPv6(Layer):
    _my__protocol = ProtocolTypes.IPv6
    _mac_dst_addr = "33:33:ff:7a:b3:24"

    version        = None  # Is 6
    traffic_class  = None  # Something with QoS?
    flow_label     = None
    payload_length = None  # Just data len
    nextheader     = None  # AKA "protocol" field in ipv4
    hoplimit       = None  # Literally the same as TTL
    psrc           = None  # Source IP
    pdst           = None  # Destination IP

    def __init__(self, *, psrc=None, pdst=None, nextheader=None, traffic_class=None, flow_label=None, hoplimit=None, ttl=None):
        self.traffic_class = traffic_class
        self.flow_label    = flow_label
        self.nextheader    = nextheader
        self.hoplimit      = hoplimit or ttl
        self.psrc          = psrc
        self.pdst          = pdst

    def __bytes__(self):
        """
        Returns the binary representation of the IPv6 packet.
        """
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
        pkt += struct.pack('!BB', self.nextheader, self.hoplimit)
        pkt += srcbytes
        pkt += dstbytes
        if hasattr(self, 'data'):
            if isinstance(self.data, ICMPv6 | UDP):
                pkt += self.data.toBytes(srcbytes, dstbytes)
            else:
                pkt += bytes(self.data)
        return pkt

    def _autocomplete(self):
        """
        Autocompletes the packet.
        """

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
            try:
                self.hoplimit = self.data._hoplimit
            except AttributeError:
                self.hoplimit = 64

        if self.psrc is None:
            self.psrc = getIpv6Addr(conf.iface)

        if self.pdst is None:
            try:
                self.pdst = self.data._ipdst__addr
            except AttributeError:
                print("WARNING: Destination IP not specified, fe80::1 will be used")
                self.pdst = "fe80::1"

        try:
            self.nextheader = self.data._my__protocol
        except AttributeError:
            self.nextheader = ProtocolTypesIP.IPv6_NoNxt

    def __len__(self):
        return 4+2+1+1+16+16+len(self.data)


# https://datatracker.ietf.org/doc/html/rfc2460#section-4.2
class ExtensionHeader(metaclass=ABCMeta):
    """
    Abstract Base Class for IPv6 Extension Header
    """

class HopByHopExtHdr(ExtensionHeader):
    def __init__(self):
        super(HopByHopExtHdr, self).__init__()

# https://datatracker.ietf.org/doc/html/rfc2460#section-4.5
class FragExtHdr(ExtensionHeader, Layer):
    _my__protocol = ProtocolTypesIP.IPv6_frag
    data = b''

    def __init__(self, frag_offset=None, res=None, flagM=None, id_=None):
        # length is 0 because of fixed size, so reserved.
        super(FragExtHdr, self).__init__()

        self.frag_offset = frag_offset
        self.res         = res
        self.flagM       = flagM
        self.id_         = id_

    def __bytes__(self):
        self._autocomplete()
        pkt = struct.pack("!B", self.nextheader)
        pkt += b'\x00'
        pkt += struct.pack("!H", (self.frag_offset << 3) | (self.res << 1) | self.flagM)
        pkt += struct.pack("!L", self.id_)
        pkt += bytes(self.data)
        return pkt

    def __len__(self):
        return 1+1+2+4+len(self.data)

    def _autocomplete(self):
        if self.id_ is None:
            self.id_ = RandInt()

        if self.flagM is None:
            self.flagM = False

        if self.frag_offset is None:
            self.frag_offset = 0x0

        if self.res is None:
            # reserved 2 bits
            self.res = 0

        try:
            self.nextheader = self.data._my__protocol
        except AttributeError:
            self.nextheader = ProtocolTypesIP.IPv6_NoNxt
