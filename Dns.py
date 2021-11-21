import struct

from Layer import Layer
from Values import RandShort, ipv4ToBytes, isIpv4, Bidict


# noinspection SpellCheckingInspection
# https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
class QTYPES:
    A       = 0x1
    AAAA    = 0x1c
    CNAME   = 0x5
    NS      = 0x2
    SOA     = 0x6
    MX      = 0xf
    ALL     = 0xff

QTYPES_dict = Bidict(vars(QTYPES))

# noinspection SpellCheckingInspection
# https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
class DNSQR(Layer):
    qname    = None
    qtype    = None # https://en.wikipedia.org/wiki/List_of_DNS_record_types#Resource_records
    qclass   = None # https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3

    def __init__(self, qname, *, qtype=None, qclass=None):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def __str__(self):
        self._autocomplete()
        self.qtype = QTYPES_dict[self.qtype]
        ret = super(DNSQR, self).__str__()
        self.qtype = QTYPES_dict[self.qtype]
        return ret

    def __bytes__(self):
        self._autocomplete()
        # qname works like this:
        # Instead of every `.`, comes the length following the `.`, and the string ends with \x00. example:
        # Query:  www.google.com
        # www.google.com => www.google.com. => 3www6google3com0
        domain = self.qname.strip('.').split('.')
        qname = b''

        for part in domain:
            qname += struct.pack("!B", len(part))
            qname += part.encode()
        qname += b'\x00'
        pkt = qname
        pkt += struct.pack("!HH", self.qtype, self.qclass)
        return pkt

    def _autocomplete(self):
        if self.qtype is None:
            self.qtype = QTYPES.A
        if self.qclass is None:
            self.qclass = 0x1

# noinspection SpellCheckingInspection
# https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
class DNSRR(Layer):
    name       = None
    type       = None
    class_     = None
    ttl        = None
    rdlength   = None
    rdata      = None

    def __init__(self, name=None, type=None, class_=None, ttl=None, rdata=None):
        self.name   = name
        self.type   = type
        self.class_ = class_
        self.ttl    = ttl
        self.rdata  = rdata

    def __str__(self):
        self.type = QTYPES_dict[self.type]
        ret = super(DNSRR, self).__str__()
        self.type = QTYPES_dict[self.type]
        return ret

    def __bytes__(self):
        self._autocompelte()
        domain = self.name.strip('.').split('.')
        name = b''

        for part in domain:
            name += struct.pack("!B", len(part))
            name += part.encode()
        name += b'\x00'

        pkt = name
        pkt += struct.pack("!HHLH", self.type, self.class_, self.ttl, len(self.rdata))
        pkt += self.rdata

        return pkt

    def _autocompelte(self):
        if self.ttl is None:
            self.ttl = 0x0  # means don't cache.
        if self.type is None:
            self.type = QTYPES.A
        if self.class_ is None:
            self.class_ = 0x1

        if not isinstance(self.rdata, bytes) and isIpv4(self.rdata):
            self.rdata = ipv4ToBytes(self.rdata)


# noinspection SpellCheckingInspection
class DNS(Layer):
    id          = None
    qr          = 0  # 0=query  1=answer
    opcode      = 0  # 0=standard query  1=inverse query  2=status  3-15 reserved lmfao
    AA          = 0
    tc          = 0
    rd          = 1
    ra          = 0
    Z           = 0x0
    rcode       = 0

    qdcount    = None
    ancount    = None
    nscount    = None
    arcount    = None

    def __init__(self, qd=None, an=None, ns=None, ar=None, rd=None, qr=None, ra=None, opcode=None, rcode=None, id=None,
                 qdcount=None, ancount=None, nscount=None, arcount=None):
        assert isinstance(qd, DNSQR | None | list), "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\bValueError: qd should be of type DNSQR (DNS Query Record)"
        assert isinstance(an, DNSRR | None | list), "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\bValueError: an should be of type DNSRR (DNS Resource Record)"

        self.rd = rd
        self.qr = qr
        self.ra = ra

        self.id = id
        self.opcode = opcode
        self.rcode = rcode

        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

        self.qd = qd
        self.an = an
        self.ns = ns
        self.ar = ar

    def __bytes__(self):
        self._autocomplete()

        byte2 = (self.qr << 15) | (self.opcode << 11) | (self.AA << 10) | (self.tc << 9) | (self.rd << 8)\
                | (self.ra << 7) | (self.Z << 4) | self.rcode

        pkt = struct.pack('!HHHHHH', self.id, byte2, self.qdcount, self.ancount, self.nscount, self.arcount)
        if self.qd:
            pkt += b''.join(bytes(x) for x in self.qd)
        if self.an:
            pkt += b''.join(bytes(x) for x in self.an)
        if self.ns:
            pkt += b''.join(bytes(x) for x in self.ns)
        if self.ar:
            pkt += b''.join(bytes(x) for x in self.ar)

        if hasattr(self, 'data'):
            pkt += bytes(self.data)
        return pkt

    def _autocomplete(self):
        if self.id is None:
            self.id = RandShort()

        if self.rd is None:
            self.rd = 0x1

        if self.opcode is None:
            self.opcode = 0

        if self.rcode is None:
            self.rcode = 0

        if self.qr is None:
            self.qr = 0

        if self.ra is None:
            self.ra = self.qr

        if not isinstance(self.qd, list) and self.qd:
            self.qd = [self.qd]
        if not isinstance(self.an, list) and self.an:
            self.an = [self.an]
        if not isinstance(self.ns, list) and self.ns:
            self.ns = [self.ns]
        if not isinstance(self.ar, list) and self.ar:
            self.ar = [self.ar]

        self.qdcount = int(len(self.qd)) if self.qd else 0
        self.ancount = int(len(self.an)) if self.an else 0
        self.nscount = int(len(self.ns)) if self.ns else 0
        self.arcount = int(len(self.ar)) if self.ar else 0
