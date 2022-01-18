import struct
import conf
from Layer import Layer
from HelperFuncs import *
from abc import ABCMeta, abstractmethod
# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6

class ICMPv6(Layer, metaclass=ABCMeta):
    _my__protocol = ProtocolTypesIP.ICMPv6

    type   = None
    code   = None
    chksum = None  # Using chksum16bit
    msg    = b''

    @abstractmethod
    def __init__(self, type=None, code=None, chksum=None):
        self.type = type
        self.code = code
        self.chksum = chksum

    @abstractmethod
    def __bytes__(self):
        pkt = struct.pack("!BB", self.type, self.code)
        return pkt
