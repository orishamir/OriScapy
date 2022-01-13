import Ethernet
from Layer import Layer
import struct
from HelperFuncs import *
# https://datatracker.ietf.org/doc/html/rfc2460#section-3

class IPv6(Layer):
    version = None
    traffic_class = None   # Something with QoS?
    flow_label = None
    payload_length = None
    protocol = None         # RFC calls this "Next Header"...
    hoplimit = None         # Literally the same as TTL
    psrc = None
    pdst = None

    def __init__(self, psrc=None, pdst=None):
        self.psrc = psrc
        self.pdst = pdst

    def __bytes__(self):
        self._autocomplete()
        srcbytes = ipv6ToBytes(self.psrc)
        dstbytes = ipv6ToBytes(self.pdst)
        pkt = b''
        first_2_bytes = (self.version << 28) | (self.traffic_class << 20) | self.flow_label
        pkt += struct.pack("!L", first_2_bytes)
        pkt += struct.pack('!H', self.payload_length)
        pkt += struct.pack('!BB', self.protocol, self.hoplimit)
        pkt += srcbytes
        pkt += dstbytes
        return pkt

    def _autocomplete(self):
        if self.version is None:
            self.version = 6

        if self.traffic_class is None:
            self.traffic_class = 0

        if self.flow_label is None:
            self.flow_label = 0

        if self.payload_length is None:
            if self.data:
                self.payload_length = len(self.data)
            else:
                self.payload_length = 0

        if self.protocol is None:
            self.protocol = ProtocolTypesIP.IPv6_NoNxt

        if self.hoplimit is None:
            self.hoplimit = 64