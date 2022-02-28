import struct
import conf
from HelperFuncs import ProtocolTypesIP, chksum16bit, Icmpv6Types, mac2bytes, getMacAddr, ipv6ToBytes, Bidict
from Icmpv6 import ICMPv6
from abc import ABCMeta, abstractmethod
from Layer import Layer

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
class NDPOption(Layer, metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, type=None, length=None):
        self.type = type
        self.length = length

    @abstractmethod
    def __bytes__(self):
        assert self.type is not None and self.length is not None
        return struct.pack("!BB", self.type, self.length)

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.6.4
class NdpMTUOption(NDPOption):
    def __init__(self, mtu=1500):
        super(NdpMTUOption, self).__init__(type=OptionTypes.MTU, length=1)
        self.mtu = mtu

    def __bytes__(self):
        pkt = super(NdpMTUOption, self).__bytes__()  # type and length
        pkt += b'\x00\x00'  # Reserved
        pkt += struct.pack("!L", self.mtu)
        return pkt

    def __len__(self):
        return 1+1+2+4

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

    def __len__(self):
        return 1+1+6

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.6.2
class NdpPrefixInfoOption(NDPOption):
    def __init__(self, prefixlen, flagL, flagA, flagR, validlifetime, preflifetime, prefix):
        super(NdpPrefixInfoOption, self).__init__(type=OptionTypes.prefix_info, length=4)

        self.prefixlen = prefixlen
        self.flagL = flagL
        self.flagA = flagA
        self.flagR = flagR
        self.validlifetime = validlifetime
        self.preflifetime = preflifetime
        self.prefix = prefix

    def __bytes__(self):
        pkt = super(NdpPrefixInfoOption, self).__bytes__()  # type and length
        pkt += struct.pack("!BB", self.prefixlen, (self.flagL << 7) | (self.flagA << 6) | (self.flagR << 5))
        pkt += struct.pack("!LL", self.validlifetime, self.preflifetime)
        pkt += b'\x00'*4
        pkt += ipv6ToBytes(self.prefix)
        return pkt

    def __len__(self):
        return 1+1+1+1+4+4+4+16

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

    def __len__(self):
        return 1+1+2+4+len(self.addresses)*16

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.2
class NDPRouterAdv(ICMPv6):
    _hoplimit = 255
    _options = []

    def __init__(self, lladdr, prefix, curhoplimit=64, flagM=False, flagO=False, lifetime=None, reachabletime=None,
                 retranstime=None, options=None):
        super(NDPRouterAdv, self).__init__(type=Icmpv6Types.router_adv, code=0)
        self.lladdr = lladdr
        self.prefix = prefix
        self.curhoplimit = curhoplimit
        self.flagM = flagM
        self.flagO = flagO
        self.flagH = 0
        self.flagPrf = 0b01
        self.flagProx = 0
        self.lifetime = lifetime
        self.reachabletime = reachabletime
        self.retranstime = retranstime
        if options is None:
            self._options = []
        else:
            self._options = options

        self._autocomplete()

    def __len__(self):
        return 1+1+2+1+1+2+4+4+sum(len(op) for op in self._options)

    def toBytes(self, srcipbytes, dstipbytes):
        self._autocomplete()

        pkt = super(NDPRouterAdv, self).__bytes__()  # type and code
        pkt += b'\x00\x00'  # checksum
        pkt += struct.pack("!BBH", self.curhoplimit, (self.flagM << 7) | (self.flagO << 6) | (self.flagH << 5)
                           | (self.flagPrf << 3) | (self.flagProx << 1),
                           self.lifetime)
        pkt += struct.pack("!LL", self.reachabletime, self.retranstime)
        for option in self._options:
            pkt += bytes(option)

        tochecksum = pkt + self._get_pseudo_header(srcipbytes, dstipbytes)
        pkt = pkt[:2] + struct.pack("!H", chksum16bit(tochecksum)) + pkt[4:]
        return pkt

    def _autocomplete(self):
        if self.lifetime is None:
            self.lifetime = 100

        if self.reachabletime is None:
            self.reachabletime = 10000

        if self.retranstime is None:
            self.retranstime = 10000

        if not self._options:
            # generate options automatically
            options = []
            mtuoption = NdpMTUOption()
            sourcell = NdpLLAddrOption(issrc=True, addr=self.lladdr)
            prefixinfo = NdpPrefixInfoOption(64, 1, 1, 1, self.lifetime, self.lifetime, self.prefix)

            options.append(mtuoption)
            options.append(sourcell)
            options.append(prefixinfo)
            self._options = options

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.1
class NDPRouterSol(ICMPv6):
    _hoplimit = 255
    _options = []

    def __init__(self, lladdr=None):
        super(NDPRouterSol, self).__init__(type=Icmpv6Types.router_soli, code=0)
        if lladdr is None:
            lladdr = getMacAddr(conf.iface)

        self.lladdr = lladdr
        self._options = []
        self._options.append(NdpLLAddrOption(issrc=True, addr=self.lladdr))

    def __len__(self):
        return 1+1+2+4+sum(len(op) for op in self._options)

    def toBytes(self, srcipbytes, dstipbytes):
        pkt = super(NDPRouterSol, self).__bytes__()  # type and code
        pkt += b'\x00\x00'  # checksum
        pkt += b'\x00'*4  # reserved
        for option in self._options:
            pkt += bytes(option)

        tochecksum = pkt + self._get_pseudo_header(srcipbytes, dstipbytes)
        pkt = pkt[:2] + struct.pack("!H", chksum16bit(tochecksum)) + pkt[4:]
        return pkt

# https://datatracker.ietf.org/doc/html/rfc4861#section-4.3
class NDPQuery(ICMPv6):
    _hoplimit = 255
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
