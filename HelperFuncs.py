import netifaces as _netifaces
import struct as _struct
import random as _random
from re import findall as _findall

def checksum(packet):
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
    zeroOctets = 8-ip.count(':')

    ip = ip.replace('::', ':0000:'*zeroOctets).replace('::', ':')
    ret = b''
    for octet in ip.split(':'):
        bt = hex(int(octet, 16))[2:].zfill(4)
        ret += _struct.pack('BB', *[int(x, 16) for x in _findall('..', bt)])

    assert len(ret) == 16, f"ipv6 to bytes error {ip=}"
    return ret

def bytesToIpv4(bts: bytes):
    assert len(bts) == 4, 'IPv4 should have 4 bytes'
    return '.'.join(map(str, bts))

def bytesToMac(bts: bytes):
    assert len(bts) == 6, 'MAC Address should be 6 bytes'
    return ':'.join(hex(x)[2:].zfill(2) for x in bts)

def isIpv4(ip: str):
    try:
        ipv4ToBytes(ip)
    except ValueError:
        return False
    return True

def isIpv6(ip: str):
    try:
        ipv6ToBytes(ip)
    except ValueError:
        return False
    return True

def getMacAddr(iface):
    return _netifaces.ifaddresses(iface)[_netifaces.AF_LINK][0]['addr']

def getIpAddr(iface):
    return _netifaces.ifaddresses(iface)[_netifaces.AF_INET][0]['addr']

def addr2concatbits(addr):
    return ''.join(bin(i)[2:].zfill(8) for i in _struct.pack('BBBB', *map(int, addr.split('.'))))

def getSubnetmask(iface):
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
    if tstIp == '255.255.255.255' or tstIp == b'\xff\xff\xff\xff':
        return True
    mask = bin(mask)[2:]
    mask = mask.replace('0', 'a').replace('1', '0').replace('a', '1')
    mask = int(mask, 2)
    host_part = bin(int(addr2concatbits(tstIp), 2) & mask)[2:]
    return len(host_part) == host_part.count('1')

def isMulticastAddr(tstIp: str):
    octets = tstIp.split('.')
    if octets[0] == '224':
        return octets[1] in ('0', '1', '3')
    elif octets[0] in range(225, 238+1):
        return True
    elif octets[0] == '239':
        return True
    return False

def RandShort():
    return _random.randint(2000, 2**16-100)

class ProtocolTypes:
    # https://en.wikipedia.org/wiki/EtherType#Values
    IPv4    = 0x0800
    IPv6    = 0x86dd
    ARP     = 0x0806
    default = 0x9000

class AddressesType:
    _ipv6_broadcast = ""  # does not exist lol
    mac_broadcast = "ff:ff:ff:ff:ff:ff"
    ipv4_broadcast = "255.255.255.255"

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

        self.inverse = {}
        # make this a 1-liner?
        for key, val in self.items():
            self.inverse[val] = key

    def __getitem__(self, item):
        if item in self.inverse:
            return self.inverse.__getitem__(item)
        return super(Bidict, self).__getitem__(item)

    def __setitem__(self, key, value):
        super(Bidict, self).__setitem__(key, value)
        self.inverse.__setitem__(value, key)

    def __str__(self):
        return f"{super(Bidict, self).__str__()}+{self.inverse.__str__()}"

ProtocolTypes_dict = Bidict(ProtocolTypes.__dict__)
