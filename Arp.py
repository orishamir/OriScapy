import conf
from Layer import Layer
from HelperFuncs import Bidict, mac2bytes, ipv4ToBytes, ProtocolTypes, \
    ProtocolTypes_dict, AddressesType, getMacAddr, getIpAddr
import struct

# https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure

# RFC for arp:
# https://datatracker.ietf.org/doc/html/rfc826

# ARP parameters:
# https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml

class Opcodes:
    Request = 0x1
    Reply = 0x2
OPCODES_DICT = Bidict(vars(Opcodes))

class HardwareTypes:
    # https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
    Ethernet = 0x1
    Dot11 = 0x6
    FrameRelay = 0xf
    HDLC = 0x11
    Serial = 0x14  # PPP?
HardwareTypes_dict = Bidict(vars(HardwareTypes))

# ptype: ipv4
# hwtype: ethernet
# opcode: request/response

# noinspection SpellCheckingInspection
class ARP(Layer):
    _my__protocol = ProtocolTypes.ARP
    _mac_dst_addr = "ff:ff:ff:ff:ff:ff"

    hwtype  =  HardwareTypes.Ethernet
    ptype   =  ProtocolTypes.IPv4
    hardwareSize =  6
    psize   =  4
    opcode  =  Opcodes.Request
    hwsrc   =  None
    psrc    =  None
    hwdst   =  None
    pdst    =  None

    def __init__(self, *, hwtype=HardwareTypes.Ethernet, ptype=ProtocolTypes.IPv4, opcode=Opcodes.Request,
                 pdst=None, hwdst=None, psrc=None, hwsrc=None, psize=4, hwsize=6):
        self.hwtype  =  hwtype
        self.ptype   =  ptype
        self.hwsize  =  hwsize
        self.psize   =  psize
        self.opcode  =  opcode
        self.pdst    =  pdst
        self.hwdst   =  hwdst
        self.psrc    =  psrc
        self.hwsrc   =  hwsrc

    def __bytes__(self):
        self._autocomplete()
        # convert to bytes
        ret = struct.pack("!HHBBH", self.hwtype, self.ptype, self.hardwareSize, self.psize, self.opcode)
        ret += mac2bytes(self.hwsrc)
        ret += ipv4ToBytes(self.psrc)

        ret += mac2bytes(self.hwdst)
        ret += ipv4ToBytes(self.pdst)
        return ret

    def _autocomplete(self):
        # Some parameters missing, complete automatically

        if self.hwdst is None:
            self.hwdst = AddressesType.mac_broadcast

        if self.hwsrc is None:
            self.hwsrc = getMacAddr(conf.iface)

        if self.psrc is None:
            self.psrc = getIpAddr(conf.iface)

    def __str__(self):
        self.opcode = OPCODES_DICT.get(self.opcode, None)
        self.hwtype = HardwareTypes_dict.get(self.hwtype, None)
        self.ptype = ProtocolTypes_dict.get(self.ptype, None)
        ret = super(ARP, self).__str__()
        self.opcode = OPCODES_DICT.get(self.opcode, None)
        self.hwtype = HardwareTypes_dict.get(self.hwtype, None)
        self.ptype = ProtocolTypes_dict.get(self.ptype, None)
        return ret
