import struct

from Layer import Layer
from HelperFuncs import RandShort, ProtocolTypesIP, chksum16bit


# noinspection SpellCheckingInspection
# https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure
class UDP(Layer):
    _my__protocol = ProtocolTypesIP.UDP
    sport     =   None
    dport     =   None
    length    =   None
    checksum  =   None

    data = b''

    def __init__(self, *, sport=None, dport=None):
        self.sport = sport
        self.dport = dport

    def __bytes__(self):
        self._autocomplete()
        pkt = struct.pack("!HHHH", self.sport, self.dport, self.length, 0)
        pkt += bytes(self.data)
        return pkt

    def toBytes(self, srcbytes, dstbytes):
        self._autocomplete()
        pkt = struct.pack("!HHHH", self.sport, self.dport, self.length, 0)
        pkt += bytes(self.data)

        tochecksum = self._get_pseudo_header(srcbytes, dstbytes)
        tochecksum += pkt
        self.checksum = chksum16bit(tochecksum)

        pkt = pkt[:6] + struct.pack("!H", self.checksum) + pkt[8:]
        return pkt

    def _get_pseudo_header(self, ipsrcbytes, ipdstbytes):
        pseudoIpv6Header = b""
        pseudoIpv6Header += ipsrcbytes
        pseudoIpv6Header += ipdstbytes
        pseudoIpv6Header += struct.pack("!H", len(self))
        pseudoIpv6Header += b"\x00"
        pseudoIpv6Header += struct.pack("!B", ProtocolTypesIP.UDP)
        return pseudoIpv6Header

    def _autocomplete(self):
        if self.sport is None:
            self.sport = RandShort()
        if self.dport is None:
            raise ValueError("Destionation Port in UDP header empty.")
        self.length = 8 + len(self.data)
    
    def __len__(self):
        return 2+2+2+2+len(self.data)
