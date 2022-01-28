import struct

from Layer import Layer
from HelperFuncs import RandShort, ProtocolTypesIP

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

    def _autocomplete(self):
        if self.sport is None:
            self.sport = RandShort()
        if self.dport is None:
            raise ValueError("Destionation Port in UDP header empty.")

        self.length = 8 + len(self.data)
    
    def __len__(self):
        return 2+2+2+2+len(self.data)