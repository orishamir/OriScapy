from Layer import Layer
from HelperFuncs import *
from Arp import ARP
from Ip import IP
import Sendreceive
import conf
import struct
from Ipv6 import IPv6

# Ben Eater - "How do CRCs work?"
# https://www.youtube.com/watch?v=izG7qT0EpBw

"""
To summarize very badly, you convert the data to a polynomial 
depending on the index of the bit and its value (0/1) s.t. index is the power and value is the coef
After that you perform a polynomial division with a Generator Polynomial.
https://en.wikipedia.org/wiki/Cyclic_redundancy_check#Polynomial_representations_of_cyclic_redundancy_checks

For crc32, the generator polynomial is:
x³² + x²⁶+x²³+x²²+x¹⁶+x¹²+x¹¹+x¹⁰+x⁸+x⁷+x⁵+x⁴+x²+x+1 

Let m(x) be the polynomial representation of your message data
Let g(x) be the Generator Polynomial.
# Let e(x) be the error represented as a polynomial.
Let r(x) be the remainder polynomial of m(x)/g(x)

After generating r(x), you shall transmit m(x)<<32 - r(x)
that is because you'd want your receiver to simply perform
received_polynomial % g(x) and if that's 0, then the msg was received correctly

"""

# https://en.wikipedia.org/wiki/Cyclic_redundancy_check

# noinspection SpellCheckingInspection
# https://en.wikipedia.org/wiki/Ethernet_frame#Structure
class Ether(Layer):
    dst = None
    src = None
    etherType = None
    data = b''
    checksum = None

    def __init__(self, *, dst=None, src=None, ethType=None):
        self.dst = dst
        self.src = src
        self.etherType = ethType

        if self.src is None:
            self.src = getMacAddr(conf.iface)

    def __bytes__(self):
        # return as raw bytes
        """
        Ethernet Header:
        ---     Dst addr    --- 6 bytes
        ---     src addr    --- 6 bytes
        ---     EtherType   --- 2 bytes
        data             .......
        ---  CRC checksum   --- 4 bytes

        """
        self._autocomplete()
        if not self.dst:
            raise TypeError("Destination MAC not set")
        if not self.src:
            raise TypeError("Source MAC not set")

        if not hasattr(self, 'data'):
            self.data = b''
            dataBytes = b''
        else:
            dataBytes = self.data.__bytes__()
        if not isinstance(dataBytes, list):
            dataBytes = [dataBytes]

        ret = []
        for dataByte in dataBytes:
            tmp_ret = b''
            tmp_ret += mac2bytes(self.dst)
            tmp_ret += mac2bytes(self.src)
            tmp_ret += struct.pack(">H", self.etherType)
            tmp_ret += dataByte
            tmp_ret += struct.pack("<L", crc32(tmp_ret))
            ret.append(tmp_ret)
        return ret

    def _autocomplete(self):
        if self.src is None:
            self.src = getMacAddr(conf.iface)
        if not hasattr(self, 'data'):
            return
        # Determine self.etherType based on data
        if self.etherType is None:
            try:
                self.etherType = self.data._my__protocol
            except AttributeError:
                pass
        if self.dst is None:
            try:
                self.dst = self.data._mac_dst_addr
            except AttributeError:
                pass
        # if self.etherType == ProtocolTypes.IPv4:
        #     pass

        if isinstance(self.data, IP | IPv6):
            # if isinstance(self.data, IPv6):
            #     self.etherType = ProtocolTypes.IPv6
            # else:
            #     self.etherType = ProtocolTypes.IPv4
            if self.dst is None:
                # resolve ip to mac automatically
                # send arp and receive automatically.
                if IPv6 in self:
                    raise NotImplementedError("Ethernet autocompletion for IPv6 not implemented yet")
                # if IP in self:
                dst_ip = self[IP].pdst
                # If same subnet, use the direct PC's mac
                mask = getSubnetmask(conf.iface)
                if isMulticastAddr(dst_ip):
                    print("WARNING: dst MAC address not specified when sending multicast. Set automatically to broadcast")
                    self.dst = "ff:ff:ff:ff:ff:ff"
                elif isBroadCastAddr(dst_ip, mask):
                    self.dst = "ff:ff:ff:ff:ff:ff"
                elif isSameSubnet(dst_ip, getIpAddr(conf.iface), mask):
                    _resolve = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=dst_ip)
                    self.dst = Sendreceive.sendreceive(_resolve)[ARP].hwsrc
                else:
                    # else send to router
                    _resolve = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=getDefaultGateway(conf.iface))
                    # print(_resolve.etherType)
                    self.dst = Sendreceive.sendreceive(_resolve, timeout=10)[ARP].hwsrc

    def __str__(self):
        self.etherType = ProtocolTypes_dict.get(self.etherType, None)
        ret = super(Ether, self).__str__()
        self.etherType = ProtocolTypes_dict.get(self.etherType, None)
        return ret

    def __len__(self):
        return 6+6+2+len(self.data)
