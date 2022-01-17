# https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5
# https://datatracker.ietf.org/doc/html/rfc4861#section-4.6
import struct

import conf
from HelperFuncs import ProtocolTypesIP, chksum16bit, Icmpv6Types, mac2bytes, getMacAddr, ipv6ToBytes
from Icmpv6 import ICMPv6


class OptionTypes:
    source_link_addr = 1
    target_link_addr = 2
    prefix_info      = 3
    redirect_header  = 4
    MTU              = 5

class NDPOption:
    def __init__(self, type=None, length=None):
        self.type = type
        self.length = length

    def __bytes__(self):
        return struct.pack("!BB", self.type, self.length)

class NDPMTUOption(NDPOption):
    def __init__(self, mtu=1500, ):
        super(NDPMTUOption, self).__init__(type=OptionTypes.MTU, length=4)

    def __str__(self):
        return f"MTUOption: type={self.type} length={self.length}"

class NDPSrcOption(NDPOption):
    pass

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.2
class NDPRouterAdv(ICMPv6):
    _ipdst__addr = "fe80::1"  # Destination address for IPv6 header to use
    options = []

    hoplimit = 64
    flagM    = False
    flagO    = False
    lifetime = 6000
    reachabletime = 100000
    retranstime   = 100000

    def __init__(self, optionaddr=None, MTU=1500):
        raise NotImplementedError
        super(NDPRouterAdv, self).__init__(type=Icmpv6Types.router_adv, code=0)
        if optionaddr is None:
            print("Warning: NDP Query option address is None, setting to iface's mac addr")
            optionaddr = mac2bytes(getMacAddr(conf.iface))
        self.options = []
        MTUoption = NDPOption(OptionTypes.MTU, 1, b'\x00' + struct.pack("!L", MTU))
        # PrefixInfoOption = NDPOption(OptionTypes.prefix_info, 4, )
        self.options.append(MTUoption)

    def __len__(self):
        return 1+1+2+1+1+2+4+4+len(self.options)

    def toBytes(self, ipsrcbytes, ipdstbytes):
        pkt = super(NDPRouterAdv, self).__bytes__()  # ICMPv6 type and code
        pkt += b'\x00\x00'  # Checksum
        pkt += struct.pack("!BBH", self.hoplimit, (self.flagM << 7) | (self.flagO << 6), self.lifetime)
        pkt += struct.pack("!LL", self.reachabletime, self.retranstime)
        for option in self.options:
            pkt += bytes(option)  # Option

        pseudoIpv6Header = b""
        pseudoIpv6Header += ipsrcbytes
        pseudoIpv6Header += ipdstbytes
        pseudoIpv6Header += struct.pack("!H", len(self))
        pseudoIpv6Header += b"\x00"
        pseudoIpv6Header += struct.pack("!B", ProtocolTypesIP.ICMPv6)

        tochecksum = pkt + pseudoIpv6Header

        pkt = pkt[:2] + struct.pack("!H", chksum16bit(tochecksum)) + pkt[4:]
        return pkt

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

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.4
class NDPResponse(ICMPv6):
    _ipdst__addr = None  # Destination address for IPv6 header to use
    option = b''
    def __init__(self, target: str, R=False, S=True, O=True, optionaddr=None):
        super(NDPResponse, self).__init__(type=Icmpv6Types.neighbor_adv, code=0)
        self.target = target

        # self.option = NDPOption(type=OptionTypes.target_link_addr, length=1, data= b'' if optionaddr is None else
        #                          mac2bytes(optionaddr))
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
