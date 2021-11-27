from Layer import Layer
from HelperFuncs import *
from Arp import ARP
from Ip import IP
from zlib import crc32

import Sendreceive
from conf import iface
import struct

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

    checksum = None

    def __init__(self, *, dst=None, src=None, ethType=ProtocolTypes.default):
        self.dst = dst
        self.src = src
        self.etherType = ethType

        if self.src is None:
            self.src = getMacAddr(iface)

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
            self.src = getMacAddr(iface)

        # Determine self.etherType based on data
        if isinstance(self.data, ARP):
            self.etherType = ProtocolTypes.ARP
            if self.dst is None:
                self.dst = AddressesType.mac_broadcast

        elif isinstance(self.data, IP):
            self.etherType = ProtocolTypes.IPv4
            if self.dst is None:
                # resolve ip to mac automatically
                # send arp and receive automatically.
                dst_ip = self[IP].dst_ip
                if IP in self:
                    # If same subnet, use the direct PC's mac
                    if isSameSubnet(dst_ip, getIpAddr(iface), getSubnetmask(iface)):
                        _resolve = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(dst_ip=dst_ip)
                        self.dst = Sendreceive.sendreceive(_resolve)[ARP].sender_mac
                    else:
                        # else send to router
                        _resolve = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(dst_ip=getDefaultGateway(iface))
                        self.dst = Sendreceive.sendreceive(_resolve)[ARP].sender_mac


    def __str__(self):
        self.etherType = ProtocolTypes_dict[self.etherType]
        ret = super(Ether, self).__str__()
        self.etherType = ProtocolTypes_dict[self.etherType]
        return ret
