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


# ptype: ipv4
# hwtype: ethernet
# opcode: request/response

# noinspection SpellCheckingInspection
class ARP(Layer):
    class Opcodes:
        Request = 0x1
        Reply   = 0x2

    OPCODES_DICT = Bidict(vars(Opcodes))

    class HardwareTypes:
        Ethernet = 0x1
        Dot11    = 0x6

    HardwareTypes_dict = Bidict(vars(HardwareTypes))

    hardwareType =  HardwareTypes.Ethernet
    protocolType =  ProtocolTypes.IPv4
    hardwareSize =  6
    protocolSize =  4
    opcode       =  Opcodes.Request
    sender_mac   =  None
    sender_ip    =  None
    target_mac   =  None
    target_ip    =  None

    def __init__(self, hwtype=HardwareTypes.Ethernet, ptype=ProtocolTypes.IPv4, opcode=Opcodes.Request,
                 pdst=None, hwdst=None, psrc=None, hwsrc=None, psize=4, hwsize=6):
        self.hardwareType =  hwtype
        self.protocolType =  ptype
        self.hwsize       =  hwsize
        self.protocolSize =  psize
        self.opcode       =  opcode
        self.target_ip    =  pdst
        self.target_mac   =  hwdst
        self.sender_ip    =  psrc
        self.sender_mac   =  hwsrc

    def __bytes__(self):
        self._autocomplete()
        # convert to bytes
        ret = struct.pack("!HHBBH", self.hardwareType, self.protocolType, self.hardwareSize, self.protocolSize, self.opcode)
        ret += mac2bytes(self.sender_mac)
        ret += ipv4ToBytes(self.sender_ip)

        ret += mac2bytes(self.target_mac)
        ret += ipv4ToBytes(self.target_ip)
        return ret

    def _autocomplete(self):
        # Some parameters missing, complete automatically

        # autocomplete dst_mac
        if self.target_mac is None:
            self.target_mac = AddressesType.mac_broadcast

        if self.sender_mac is None:
            self.sender_mac = getMacAddr(conf.iface)

        if self.sender_ip is None:
            self.sender_ip = getIpAddr(conf.iface)

    def __str__(self):
        self.opcode = self.OPCODES_DICT[self.opcode]
        self.hardwareType = self.HardwareTypes_dict[self.hardwareType]
        self.protocolType = ProtocolTypes_dict[self.protocolType]
        ret = super(ARP, self).__str__()
        self.opcode = self.OPCODES_DICT[self.opcode]
        self.hardwareType = self.HardwareTypes_dict[self.hardwareType]
        self.protocolType = ProtocolTypes_dict[self.protocolType]
        return ret
