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

# https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5
# https://datatracker.ietf.org/doc/html/rfc4861#section-4.6
class OptionTypes:
    source_link_addr = 1
    target_link_addr = 2

    redirect_header  = 4
    MTU              = 5

class NDPOption:
    # type2length = {
    #     OptionTypes.source_link_addr: 6,
    #     OptionTypes.target_link_addr: 6,
    # }
    def __init__(self, type=None, length=None, data=None):
        self.type = type
        self.length = length or 1
        self.data = data

    def __len__(self):
        return 1+1+len(self.data)#self.length*self.type2length[self.type]

    def __bytes__(self):
        return struct.pack("!BB", self.type, self.length) + self.data

    def __str__(self):
        return f"NDPOption type={self.type} length={self.length} value={hex(int(self.data.hex()))}"

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.3
class NDPQuery(ICMPv6):
    _ipdst__addr = None  # Destination address for IPv6 header to use
    option = b''

    def __init__(self, target_address: str, optionaddr=None, withOption=True):
        super(NDPQuery, self).__init__(type=Icmpv6Types.neighbor_soli, code=0)
        self.target = target_address
        self._ipdst__addr = self.target
        if withOption:
            if optionaddr is None:
                print("Warning: NDP Query option address is None, setting to iface's mac addr")
                optionaddr = mac2bytes(getMacAddr(conf.iface))
            self.option = NDPOption(type=OptionTypes.source_link_addr, length=1, data=optionaddr)

    def __len__(self):
        return 1+1+2+4+16+len(self.option)

    def toBytes(self, ipsrcbytes, ipdstbytes):
        pkt = super(NDPQuery, self).__bytes__()  # ICMPv6 type and code
        pkt += b'\x00\x00'  # Checksum
        pkt += b'\x00'*4    # Reserved
        pkt += ipv6ToBytes(self.target)  # target
        pkt += bytes(self.option)  # Option

        pseudoIpv6Header = b""
        pseudoIpv6Header += ipsrcbytes
        pseudoIpv6Header += ipdstbytes
        pseudoIpv6Header += struct.pack("!H", len(self))
        pseudoIpv6Header += b"\x00"
        pseudoIpv6Header += struct.pack("!B", ProtocolTypesIP.ICMPv6)

        tochecksum = pkt + pseudoIpv6Header

        pkt = pkt[:2] + struct.pack("!H", chksum16bit(tochecksum)) + pkt[4:]
        return pkt

class NDPResponse(ICMPv6):
    _ipdst__addr = None  # Destination address for IPv6 header to use
    option = b''
    def __init__(self, target: str, R=False, S=True, O=True, optionaddr=None):
        super(NDPResponse, self).__init__(type=Icmpv6Types.neighbor_adv, code=0)
        self.target = target

        self.option = NDPOption(type=OptionTypes.target_link_addr, length=1, data= b'' if optionaddr is None else
                                 mac2bytes(optionaddr))
        self.flagR = R
        self.flagS = S
        self.flagO = O

    def __len__(self):
        return 1+1+2+4+16+len(self.option)

    def toBytes(self, ipsrcbytes, ipdstbytes):
        pkt = super(NDPResponse, self).__bytes__()  # ICMPv6 type and code
        pkt += b'\x00\x00'  # Checksum
        pkt += struct.pack("!B", (self.flagR << 7) | (self.flagS << 6) | (self.flagO << 5))
        pkt += b'\x00' * 3  # Reserved
        pkt += ipv6ToBytes(self.target)  # target
        pkt += bytes(self.option)  # Option

        pseudoIpv6Header = b""
        pseudoIpv6Header += ipsrcbytes
        pseudoIpv6Header += ipdstbytes
        pseudoIpv6Header += struct.pack("!H", len(self))
        pseudoIpv6Header += b"\x00"
        pseudoIpv6Header += struct.pack("!B", ProtocolTypesIP.ICMPv6)

        tochecksum = pkt + pseudoIpv6Header

        pkt = pkt[:2] + struct.pack("!H", chksum16bit(tochecksum)) + pkt[4:]
        return pkt
