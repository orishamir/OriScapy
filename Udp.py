import struct

from Layer import Layer
from Values import RandShort

# noinspection SpellCheckingInspection
# https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure
class UDP(Layer):
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
            pass
        #self.data = bytes(self.data)

        self.length = 8 + len(self.data)