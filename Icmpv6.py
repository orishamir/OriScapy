import struct

from Layer import Layer
from HelperFuncs import *
# https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol
# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6
# https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol

class ICMPv6(Layer):
    _my__protocol = ProtocolTypesIP.ICMPv6
    # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6#Types
    class Types:
        dst_unreachable = 1
        time_exceeded = 3
        req = 128
        reply = 129
        router_soli = 133
        router_adv = 134
        neighbor_soli = 135
        neighbor_adv = 136
        redirect_msg = 137

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

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.3
class NDPQuery(ICMPv6):
    _dst__addr = None
    
    def __init__(self, target_address: str, withOption=False):
        super(NDPQuery, self).__init__(type=super().Types.neighbor_soli, code=0)
        self.target = target_address
        self._dst__addr = self.target
        if withOption:
            raise NotImplementedError
            # self.option = struct.pack("!BB", 1, 1)

    def __len__(self):
        return 1+1+2+4+16

    def toBytes(self, srcbytes, dstbytes):
        pkt = super(NDPQuery, self).__bytes__()
        pkt += b'\x00\x00'  # Checksum
        pkt += b'\x00'*4
        pkt += ipv6ToBytes(self.target)
        if hasattr(self, 'option'):
            # self.option += sender_macaddr
            pkt += self.option

        pseudeoIpv6Header = b""
        pseudeoIpv6Header += srcbytes
        pseudeoIpv6Header += dstbytes
        pseudeoIpv6Header += struct.pack("!H", len(self))
        pseudeoIpv6Header += b"\x00"
        pseudeoIpv6Header += struct.pack("!B", ProtocolTypesIP.ICMPv6)

        tochecksum = pkt + pseudeoIpv6Header

        pkt = pkt[:2] + struct.pack("!H", chksum16bit(tochecksum)) + pkt[4:]
        return pkt
