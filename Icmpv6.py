import struct
import conf
from Layer import Layer
from HelperFuncs import *
# https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol
# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6
# https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol

class ICMPv6(Layer):
    _my__protocol = ProtocolTypesIP.ICMPv6
    # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6#Types

    type   = None
    code   = None
    chksum = None  # Using chksum16bit
    msg    = b''
    def __init__(self, type=None, code=None, chksum=None):
        self.type = type
        self.code = code
        self.chksum = chksum

    def __bytes__(self):
        pkt = struct.pack("!BB", self.type, self.code)
        return pkt

