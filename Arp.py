from Layer import Layer
from Values import *
import struct

# https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure

# RFC for arp:
# https://datatracker.ietf.org/doc/html/rfc826

# ARP parameters:
# https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
# protocol types: https://en.wikipedia.org/wiki/EtherType#Values

# ptype: ipv4
# hwtype: ethernet
# opcode: request/response

# noinspection SpellCheckingInspection
class ARP(Layer):
    class Opcodes:
        request = 0x1
        reply   = 0x2

    OPCODES_DICT = Bidict(Opcodes.__dict__)

    class HardwareTypes:
        Ethernet = 0x1
        Dot11    = 0x6



    hardwareType =  HardwareTypes.Ethernet
    protocolType =  ProtocolTypes.IPv4
    hardwareSize =  6
    protocolSize =  4
    opcode       =  Opcodes.request
    sender_mac   =  None
    sender_ip    =  None
    target_mac   =  None
    target_ip    =  None

    def __init__(self, hwtype=HardwareTypes.Ethernet, ptype=ProtocolTypes.IPv4, opcode=Opcodes.request,
                 dst_ip=None, dst_mac=None, src_ip=None, src_mac=None, psize=4, hwsize=6):
        self.hardwareType =  hwtype
        self.protocolType =  ptype
        self.hwsize       =  hwsize
        self.protocolSize =  psize
        self.opcode       =  opcode
        self.target_ip    =  dst_ip
        self.target_mac   =  dst_mac
        self.sender_ip    =  src_ip
        self.sender_mac   =  src_mac

    def __bytes__(self):
        self._autocomplete()
        # convert to bytes
        ret = struct.pack(">HHBBH", self.hardwareType, self.protocolType, self.hardwareSize, self.protocolSize, self.opcode)
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
            self.sender_mac = getMacAddr("eth0")

        if self.sender_ip is None:
            self.sender_ip = getIpAddr("eth0")


