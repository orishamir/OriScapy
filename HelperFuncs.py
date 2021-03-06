import netifaces as _netifaces
import struct as _struct
import random as _random
from re import findall as _findall
from zlib import crc32
import ipaddress as _ipaddress

def chksum16bit(packet):
    total = 0

    # Add up 16-bit words
    num_words = len(packet) // 2
    for chunk in _struct.unpack("!%sH" % num_words, packet[0:num_words*2]):
        total += chunk

    # Add any left over byte
    if len(packet) % 2:
        total += (packet[-1]) << 8

    # Fold 32-bits into 16-bits
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total + 0x10000 & 0xffff

def mac2bytes(mac: str):
    mac = mac.replace("-", ":")
    bts = mac.split(":")
    if len(bts) != 6:
        raise ValueError(f"{mac} not in correct MAC address format")
    return _struct.pack("BBBBBB", *[int(bt, 16) for bt in bts])

def ipv4ToBytes(ip: str):
    bts = ip.split(".")
    if len(bts) != 4:
        raise ValueError(f"{ip} not in correct IPv4 format")
    return _struct.pack("BBBB", *[int(bt) for bt in bts])

def ipv6ToBytes(ip: str):
    return _ipaddress.IPv6Address(ip).packed

def bytesToIpv4(bts: bytes):
    assert len(bts) == 4, 'IPv4 should have 4 bytes'
    return '.'.join(map(str, bts))

def bytesToIpv6(bts: bytes):
    return _ipaddress.IPv6Address(bts).compressed

def bytesToMac(bts: bytes):
    assert len(bts) == 6, 'MAC Address should be 6 bytes'
    return ':'.join(hex(x)[2:].zfill(2) for x in bts)

def isIpv4(ip: str):
    # There has to be a better way to do this
    try:
        ipv4ToBytes(ip)
    except ValueError:
        return False
    return True

def isIpv6(ip: str):
    # There has to be a better way to do this
    try:
        ipv6ToBytes(ip)
    except ValueError:
        return False
    return True

def getMacAddr(iface):
    return _netifaces.ifaddresses(iface)[_netifaces.AF_LINK][0]['addr']

def getIpAddr(iface):
    return _netifaces.ifaddresses(iface)[_netifaces.AF_INET][0]['addr']

def getIpv6Addr(iface):
    # TODO: Add support for choosing which type of address to use (link-local, global, etc)
    return _netifaces.ifaddresses(iface)[_netifaces.AF_INET6][0]['addr']

def addr2concatbits(addr):
    return ''.join(bin(i)[2:].zfill(8) for i in _struct.pack('BBBB', *map(int, addr.split('.'))))

def getSubnetmask(iface: int):
    mask = _netifaces.ifaddresses(iface)[_netifaces.AF_INET][0]['netmask']
    maskBits = addr2concatbits(mask)
    return int(maskBits, 2)

def getDefaultGateway(iface):
    gateways = _netifaces.gateways()[_netifaces.AF_INET]
    for tmp_gtway, tmp_iface, _ in gateways:
        if tmp_iface == iface:
            return tmp_gtway
    raise ConnectionError("Can you even connect to the internet bro?")

def isSameSubnet(tstIp, ip, subnet):
    return int(addr2concatbits(tstIp), 2) & subnet == int(addr2concatbits(ip), 2) & subnet

def isBroadCastAddr(tstIp, mask: int):
    return tstIp == '255.255.255.255'
    net = _ipaddress.ip_network(f"{tstIp}/{mask.bit_count()}")
    return tstIp == '255.255.255.255' or net.broadcast_address == tstIp

def randomMac():
    mac = [0xde, 0xad, 3,
           _random.randint(0x00, 0x7f),
           _random.randint(0x00, 0xff),
           _random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: '%02x' % x, mac))

def randomIpv6(isLocal=False, isGlobal=False, isSolicit=False, isPrefix=False, prefixLen=64):
    if isSolicit:
        # raise NotImplementedError("Solicitation messages are not implemented yet")
        return generateSoliAddr(randomIpv6(isLocal=True))
    elif isLocal:
        start = 'fe80:'  # Link-local unicast starts with fe80::/10 but we use /64
        bytestoadd = 16//2
    elif isGlobal:
        start = '2a01'
        bytestoadd = 16-2
    elif isPrefix:
        return _randPrefix(prefixLen)
    else:
        start = ''
        bytestoadd = 16

    for i in range(bytestoadd):
        if i % 2 == 0:
            start += ':'
        start += '%02x' % _random.randint(0, 0xff)
    return start

def generateSoliAddr(unicastAddr):
    # https://datatracker.ietf.org/doc/html/rfc4291#section-2.7.1
    base = "ff02::1:ff"
    unicastAddr = _ipaddress.IPv6Address(unicastAddr).exploded
    return base + unicastAddr[-7:]

def _randPrefix(prefixLen):
    assert prefixLen % 8 == 0, "Prefix length must be a multiple of 8"  # TODO: Add support for other prefix lengths
    prefixLen //= 8
    start = '2a01'
    prefixLen -= 2

    for i in range(prefixLen):
        if i % 2 == 0:
            start += ':'
        start += '%02x' % _random.randint(0, 0xff)
    start += '::'
    return start

def randomIpv4():
    return bytesToIpv4(_random.randbytes(4))

def isMulticastAddr(tstIp: str):
    # First 4 bits of the first byte must be 0b1110
    return _ipaddress.IPv4Address(tstIp).is_multicast

def RandShort():
    return _random.randint(2000, 2**16-100)

def RandInt():
    return _random.randint(4000, 2**32-100)

class ProtocolTypes:
    # https://en.wikipedia.org/wiki/EtherType#Values
    IPv4    = 0x0800
    IPv6    = 0x86dd
    ARP     = 0x0806
    default = 0x9000
    LLDP    = 0x88CC
    EAPoL   = 0x888E

# IPv4 protocol nums: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
class ProtocolTypesIP:
    ICMP       = 0x1
    IGMP       = 0x2
    TCP        = 0x6
    UDP        = 0x11
    IPv6       = 0x29
    ICMPv6     = 0x3A
    EIGRP      = 0x58
    OSPF       = 0x59
    IPv6_NoNxt = 0x3B

    HOPOPT     = 0x00
    IPv6_route = 0x2B
    IPv6_frag  = 0x2C
    dest_opt   = 0x3C

# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6#Types
class Icmpv6Types:
    dst_unreachable = 1
    time_exceeded   = 3
    echo_request    = 128
    echo_reply      = 129
    router_soli     = 133
    router_adv      = 134
    neighbor_soli   = 135
    neighbor_adv    = 136
    redirect_msg    = 137

icmpv4TypesAndCodes = {
    0: 'echo_reply',
    3: {
        "name": 'dst_unreachable',
        0: "Net Unreachable",
        1: "Host Unreachable",
        2: "Protocol Unreachable",
        3: "Port Unreachable",
        4: "Fragmentation Needed and Don't Fragment was Set",
        5: "Source Route Failed",
        6: "Destination Network Unknown",
        7: "Destination Host Unknown",
        8: "Source Host Isolated",
        9: "Communication with Destination Network is Administratively Prohibited",
        10: "Communication with Destination Host is Administratively Prohibited",
        11: "Destination Network Unreachable for Type of Service",
        12: "Destination Host Unreachable for Type of Service",
        13: "Communication Administratively Prohibited",
        14: "Host Precedence Violation",
        15: "Precedence cutoff in effect",
    },
    11: {
        'value': 'Time Exceeded',
        0: 'Time to Live exceeded in Transit',
        1: 'Fragment Reassembly Time Exceeded'
    }
}

class AddressesType:
    _ipv6_broadcast = ""  # does not exist lol (there is multicast to all nodes tho)
    mac_broadcast   = "ff:ff:ff:ff:ff:ff"
    ipv4_broadcast  = "255.255.255.255"

    ipv4_empty = "0.0.0.0"
    ipv6_empty = "::"

    ipv4_loopback = "127.0.0.1"
    ipv6_loopback = "::1"

# A bi-directional dictionary
class Bidict(dict):
    def __init__(self, *args, **kwargs):
        super(Bidict, self).__init__(*args, **kwargs)

        # should not be here since its not general to bi-dicts
        for key in self.copy().keys():
            if key.startswith("_"):
                del self[key]

        # make this a 1-liner?
        self.inverse = {}
        for key, val in self.items():
            self.inverse[val] = key

    def __getitem__(self, item):
        if item in self.inverse:
            return self.inverse.__getitem__(item)
        return super(Bidict, self).__getitem__(item)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __setitem__(self, key, value):
        super(Bidict, self).__setitem__(key, value)
        self.inverse.__setitem__(value, key)

    def __str__(self):
        return f"{super(Bidict, self).__str__()}+{self.inverse.__str__()}"

ProtocolTypes_dict = Bidict(ProtocolTypes.__dict__)
