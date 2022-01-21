import struct
import conf
from HelperFuncs import ProtocolTypesIP, chksum16bit, Icmpv6Types, mac2bytes, getMacAddr, ipv6ToBytes, Bidict
from Icmpv6 import ICMPv6
from abc import ABCMeta, abstractmethod

# https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5
# https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol
# https://datatracker.ietf.org/doc/html/rfc4861
class OptionTypes:
    source_link_addr = 1
    target_link_addr = 2
    prefix_info      = 3
    redirect_header  = 4
    MTU              = 5

    DNSServer        = 25

OptionTypes_bidict = Bidict(vars(OptionTypes))

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.6
class NDPOption(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, type=None, length=None):
        self.type = type
        self.length = length

    @abstractmethod
    def __bytes__(self):
        assert self.type is not None and self.length is not None
        return struct.pack("!BB", self.type, self.length)

    def __str__(self):
        ret = "NDP Option:\n"
        for attr, val in self.__dict__.items():
            if attr == 'type':
                # convert type to human description
                val = f"{val} ({OptionTypes_bidict[val]})"
            ret += f"    {attr:<8}= {val}\n"
        return ret

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.6.4
class NdpMTUOption(NDPOption):
    def __init__(self, mtu=1500):
        super(NdpMTUOption, self).__init__(type=OptionTypes.MTU, length=1)
        self.mtu = mtu

    def __bytes__(self):
        pkt = super(NdpMTUOption, self).__bytes__()  # type and length
        pkt += b'\x00'  # Reserved
        pkt += struct.pack("!L", self.mtu)
        return pkt

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.6.1
class NdpLLAddrOption(NDPOption):
    # Ndp link layer address option
    def __init__(self, issrc, addr):
        if issrc:
            type_ = OptionTypes.source_link_addr
        else:
            type_ = OptionTypes.target_link_addr
        super(NdpLLAddrOption, self).__init__(type=type_, length=1)

        self.addr = addr

    def __bytes__(self):
        pkt = super(NdpLLAddrOption, self).__bytes__()  # type and length
        pkt += mac2bytes(self.addr)
        return pkt

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.6.2
class NdpPrefixInfoOption(NDPOption):
    def __init__(self, prefixlen, flagL, flagA, validlifetime, preflifetime, prefix):
        super(NdpPrefixInfoOption, self).__init__(type=OptionTypes.prefix_info, length=4)

        self.prefixlen = prefixlen
        self.flagL = flagL
        self.flagA = flagA
        self.validlifetime = validlifetime
        self.preflifetime = preflifetime
        self.prefix = prefix

    def __bytes__(self):
        pkt = super(NdpPrefixInfoOption, self).__bytes__()  # type and length
        pkt += struct.pack("!BB", self.prefixlen, (self.flagL << 7) | (self.flagA << 6))
        pkt += struct.pack("!LL", self.validlifetime, self.preflifetime)
        pkt += '\x00'*4
        pkt += self.prefix
        return pkt

# https://datatracker.ietf.org/doc/html/rfc8106
class NdpDnsOption(NDPOption):
    def __init__(self, lifetime, addresses):
        super(NdpDnsOption, self).__init__(type=OptionTypes.DNSServer, length=(2+2+4+len(addresses)*16)/8)
        self.lifetime = lifetime
        self.addresses = addresses

    def __bytes__(self):
        pkt = super(NdpDnsOption, self).__bytes__()  # type and length
        pkt += b'\x00'  # reserved
        pkt += struct.pack("!L", self.lifetime)
        for ip in self.addresses:
            if not isinstance(ip, bytes):
                ip = ipv6ToBytes(ip)
            pkt += ip
        return pkt

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.2
class NDPRouterAdv(ICMPv6):
    pass

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.3
class NDPQuery(ICMPv6):
    """_ipdst__addr = None  # Destination address for IPv6 header to use
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
        return pkt"""

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.4
class NDPResponse(ICMPv6):
    """_ipdst__addr = None  # Destination address for IPv6 header to use
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
        return pkt"""
