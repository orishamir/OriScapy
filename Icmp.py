import struct
from Layer import Layer
from HelperFuncs import *
from HelperFuncs import RandShort

# noinspection SpellCheckingInspection
# https://datatracker.ietf.org/doc/html/rfc792
class ICMP(Layer):
    _my__protocol = ProtocolTypesIP.ICMP

    # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
    class TypesICMP:
        echo_reply         = 0
        dst_unreachable    = 3
        echo_msg           = 8
        parameter_problem  = 12
        timestamp          = 13
        timestamp_reply    = 14

    TypesICMP_dict = Bidict(vars(TypesICMP))

    class DstUnreachableCodesICMP:
        net_unreachable      = 0
        host_unreachable     = 1
        protocol_unreachable = 2
        port_unreachable     = 3
        frag_DF_conflict     = 4
        src_route_failed     = 5

    type            = None
    code            = None
    checksum        = None
    rest_of_header  = None
    data = b'abcdefghijklmnop'

    def __init__(self, *, type_=None, code=None, id=None, seq=None):
        self.type = type_
        self.code = code
        self.id   = id
        self.seq  = seq

    def __bytes__(self):
        self._autocomplete()

        pkt = struct.pack('!BBHHH', self.type, self.code, 0, self.id, self.seq)
        self.checksum = chksum16bit(pkt + self.data)
        pkt = pkt[:1+1] + struct.pack('>H', self.checksum) + pkt[1+1+2:]
        pkt += self.data
        return pkt

    def _autocomplete(self):
        if self.type is None:
            self.type = self.TypesICMP.echo_msg
        if self.code is None:
            self.code = 0

        if self.id is None:
            self.id = RandShort()

        if self.seq is None:
            self.seq = 0

    def __str__(self):
        self.type = self.TypesICMP_dict.get(self.type, None)
        ret = super(ICMP, self).__str__()
        self.type = self.TypesICMP_dict.get(self.type, None)
        return ret

    def __len(self):
        # Is this true tho?
        return 1+1+2+4+len(self.data)
