import struct
import conf
from Layer import Layer
from HelperFuncs import *
from abc import ABCMeta, abstractmethod

# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6
class ICMPv6(Layer):
    """
    Abstract Base Class for ICMPv6 Messages.
    """
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

    def __bytes__(self):
        pkt = struct.pack("!BB", self.type, self.code)
        return pkt

    def _get_pseudo_header(self, ipsrcbytes, ipdstbytes):
        pseudoIpv6Header = b""
        pseudoIpv6Header += ipsrcbytes
        pseudoIpv6Header += ipdstbytes
        pseudoIpv6Header += struct.pack("!H", len(self))
        pseudoIpv6Header += b"\x00"
        pseudoIpv6Header += struct.pack("!B", ProtocolTypesIP.ICMPv6)
        return pseudoIpv6Header

    @abstractmethod
    def toBytes(self, srcipbytes, dstipbytes):
        # toBytes method takes src and dst ip because
        # ICMPv6 uses these in the checksum (ipv6 pseudo header)
        pass

class ICMPv6DstUnreach(ICMPv6):
    _my__protocol = ProtocolTypesIP.ICMPv6
    data = b''

    def __init__(self, code=None):
        super(ICMPv6DstUnreach, self).__init__(type=Icmpv6Types.dst_unreachable, code=code)

    def toBytes(self, ipsrcbytes, ipdstbytes):
        pkt = super(self.__class__, self).__bytes__()  # ICMPv6 type and code
        pkt += b'\x00\x00'  # Checksum
        pkt += b'\x00'*4      # Reserved
        pkt += bytes(self.data)  # original

        tochecksum = pkt + self._get_pseudo_header(ipsrcbytes, ipdstbytes)

        pkt = pkt[:2] + struct.pack("!H", chksum16bit(tochecksum)) + pkt[4:]
        return pkt

    def __len__(self):
        return 1+1+2+4+len(self.data)

# https://datatracker.ietf.org/doc/html/rfc4443#section-4.1
class ICMPv6EchoRequest(ICMPv6):
    _my__protocol = ProtocolTypesIP.ICMPv6
    id = None
    seq = None
    data = b''

    def __init__(self, id=None, seq=None, code=None):
        if code is None:
            code = 0
        super(ICMPv6EchoRequest, self).__init__(type=Icmpv6Types.echo_request, code=code)
        self.id = id
        self.seq = seq

    def toBytes(self, ipsrcbytes, ipdstbytes):
        pkt = super(self.__class__, self).__bytes__()  # ICMPv6 type and code
        pkt += struct.pack("!H", self.id)
        pkt += struct.pack("!H", self.seq)
        pkt += bytes(self.data)  # add data to packet

        tochecksum = pkt + self._get_pseudo_header(ipsrcbytes, ipdstbytes)

        pkt = pkt[:2] + struct.pack("!H", chksum16bit(tochecksum)) + pkt[4:]
        return pkt

    def __len__(self):
        return 1+1+2+2+2+len(self.data)

# https://datatracker.ietf.org/doc/html/rfc4443#section-4.2
class ICMPv6EchoReply(ICMPv6):
    _my__protocol = ProtocolTypesIP.ICMPv6
    id = None
    seq = None
    data = b''

    def __init__(self, id=None, seq=None, code=None):
        if code is None:
            code = 0
        super(ICMPv6EchoReply, self).__init__(type=Icmpv6Types.echo_reply, code=code)
        self.id = id
        self.seq = seq

    def toBytes(self, ipsrcbytes, ipdstbytes):
        pkt = super(self.__class__, self).__bytes__()  # ICMPv6 type and code
        pkt += struct.pack("!H", self.id)
        pkt += struct.pack("!H", self.seq)
        pkt += bytes(self.data)  # add data to packet

        tochecksum = pkt + self._get_pseudo_header(ipsrcbytes, ipdstbytes)

        pkt = pkt[:2] + struct.pack("!H", chksum16bit(tochecksum)) + pkt[4:]
        return pkt

    def __len__(self):
        return 1+1+2+2+2+len(self.data)