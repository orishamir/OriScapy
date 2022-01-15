import struct
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

# https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5
# https://datatracker.ietf.org/doc/html/rfc4861#section-4.6
class NDPOption:
    pass

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.3
class NDPQuery(ICMPv6):
    _dst__addr = None
    option = b''

    def __init__(self, target_address: str, withOption=False):
        super(NDPQuery, self).__init__(type=Icmpv6Types.neighbor_soli, code=0)
        self.target = target_address
        self._dst__addr = self.target
        if withOption:
            raise NotImplementedError
            # self.option = struct.pack("!BB", 1, 1)

    def __len__(self):
        return 1+1+2+4+16+len(self.option)

    def toBytes(self, srcbytes, dstbytes):
        pkt = super(NDPQuery, self).__bytes__()  # ICMPv6 type and code
        pkt += b'\x00\x00'  # Checksum
        pkt += b'\x00'*4    # Reserved
        pkt += ipv6ToBytes(self.target)  # target
        pkt += self.option  # Option

        pseudoIpv6Header = b""
        pseudoIpv6Header += srcbytes
        pseudoIpv6Header += dstbytes
        pseudoIpv6Header += struct.pack("!H", len(self))
        pseudoIpv6Header += b"\x00"
        pseudoIpv6Header += struct.pack("!B", ProtocolTypesIP.ICMPv6)

        tochecksum = pkt + pseudoIpv6Header

        pkt = pkt[:2] + struct.pack("!H", chksum16bit(tochecksum)) + pkt[4:]
        return pkt
