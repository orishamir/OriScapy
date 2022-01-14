from Layer import Layer
import struct

# https://datatracker.ietf.org/doc/html/rfc793#section-3.1
from HelperFuncs import RandShort, chksum16bit, ProtocolTypesIP

class TCP(Layer):
    _my__protocol = ProtocolTypesIP.TCP
    sport     = None
    dport     = None
    seq       = None
    ack       = None
    offset    = None   # Amount of 32-bit words in the header. Exists to determine if Options exist.
    RESERVED   = 0b000000

    flagURG   = None
    flagACK   = None
    flagPSH   = None
    flagRST   = None
    flagSYN   = None
    flagFIN   = None

    mtu       = None  # AKA window
    chksum    = None
    urgPtr    = None


    def __init__(self, sport=None, dport=None, seq=None, acknum=None):
        self.sport     = sport
        self.dport     = dport
        self.seq       = seq
        self.ack       = acknum
        self.flagURG   = None
        self.flagACK   = None
        self.flagPSH   = None
        self.flagRST   = None
        self.flagSYN   = None
        self.flagFIN   = None

    def __bytes__(self):
        self._autocomplete()

        pkt = struct.pack(">HHLL", self.sport, self.dport, self.seq, self.ack)
        pkt += struct.pack(">H", (self.offset << 12) | (self.RESERVED << 6) | (self.flagURG << 5) | (self.flagACK << 4) |
                           (self.flagPSH << 3) | (self.flagRST << 2) | (self.flagSYN << 1) | self.flagFIN)

        pkt += struct.pack(">H", self.mtu)

        # IP pseudo header included in checksum
        self.chksum = chksum16bit(pkt + struct.pack("!H", self.urgPtr))# + self.data if hasattr(self, 'data') else b'')

        pkt += struct.pack(">HH", self.chksum, self.urgPtr)

#        if hasattr(self, 'data'):
 #           pkt += bytes(self.data)

        # Insert checksum
#        pkt = pkt[:8] + struct.pack(">H", self.chksum) + pkt[10:]
        print(hex(self.chksum))

        return pkt

    def _autocomplete(self):
        if self.sport is None:
            self.sport = RandShort()
        if self.seq is None:
            self.seq = 0
        if self.ack is None:
            self.ack = 0

        if self.mtu is None:
            self.mtu = 1500
        if self.urgPtr is None:
            self.urgPtr = 0

        if self.offset is None:
            self.offset = 5

        if self.chksum is None:
            self.chksum = 0

        # Set all flags which are None to 0
        for attr in self.__dict__.keys():
            if attr.startswith('flag') and getattr(self, attr) is None:
                setattr(self, attr, 0)

