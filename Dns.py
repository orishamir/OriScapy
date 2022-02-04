import struct
from Layer import Layer
from HelperFuncs import RandShort, ipv4ToBytes, isIpv4, Bidict

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

    def __init__(self, qname="", qtype=None, qclass=None):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def __str__(self):
        self._autocomplete()
        self.qtype = QTYPES_dict.get(self.qtype, None)
        ret = super(DNSQR, self).__str__()
        self.qtype = QTYPES_dict.get(self.qtype, None)
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
    rclass     = None
    ttl        = None   # ttl in seconds (used for caching)
    rdlength   = None   # length of rdata
    rdata      = None   # the actual data

    def __init__(self, name=None, type=None, rclass=None, ttl=None, rdata=None):
        self.name   = name
        self.type   = type
        self.rclass = rclass
        self.ttl    = ttl
        self.rdata  = rdata

    def __str__(self):
        self.type = QTYPES_dict.get(self.type, None)
        ret = super(DNSRR, self).__str__()
        self.type = QTYPES_dict.get(self.type, None)
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
        pkt += struct.pack("!HHLH", self.type, self.rclass, self.ttl, len(self.rdata))
        pkt += self.rdata

        return pkt

    def _autocompelte(self):
        if self.ttl is None:
            self.ttl = 0x0  # means don't cache.
        if self.type is None:
            self.type = QTYPES.A
        if self.rclass is None:
            self.rclass = 0x1

        if not isinstance(self.rdata, bytes) and isIpv4(self.rdata):
            self.rdata = ipv4ToBytes(self.rdata)


# noinspection SpellCheckingInspection
class DNS(Layer):
    id          = None
    qr          = 0  # 0=query  1=answer
    opcode      = 0  # 0=standard query  1=inverse query  2=status  3-15 reserved lmfao
    aa          = 0  # Authorative for zone
    tc          = 0  # Was the msg truncated
    rd          = 1  # recursion desired
    ra          = 0  # recursion available
    Z           = 0x0  # reserved
    rcode       = 0  # Response code 0=noError 1=format error 2=server failure and more errors (0-5)

    qdcount    = None
    ancount    = None
    nscount    = None
    arcount    = None

    def __init__(self, qd=None, an=None, ns=None, ar=None, rd=None, qr=None, ra=None, aa=None, opcode=None, rcode=None, id=None,
                 qdcount=None, ancount=None, nscount=None, arcount=None):
        assert isinstance(qd, DNSQR | None | list), "ValueError: qd should be of type DNSQR (DNS Query Record)"
        assert isinstance(an, DNSRR | None | list), "ValueError: an should be of type DNSRR (DNS Resource Record)"

        self.aa = aa
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

        if qd and not isinstance(qd, list):
            qd = [qd]
        if an and not isinstance(an, list):
            an = [an]
        if ns and not isinstance(ns, list):
            ns = [ns]
        if ar and not isinstance(ar, list):
            ar = [ar]
        self.qd = qd
        self.an = an
        self.ns = ns
        self.ar = ar

    def __bytes__(self):
        self._autocomplete()

        byte2 = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | (self.tc << 9) | (self.rd << 8) \
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

    def __contains__(self, item):
        if super(DNS, self).__contains__(item):
            return True
        elif item is DNSQR:
            return self.qd
        elif item is DNSRR:
            return self.an
        return False

    def __getitem__(self, item):
        if item is DNSQR:
            return self.qd
        elif item is DNSRR:
            return self.an
        return super(DNS, self).__getitem__(item)

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
            self.qr = bool(self.an)

        if self.ra is None:
            self.ra = self.qr

        if self.aa is None:
            self.aa = self.qr  # if is answer then im authorative for NS

        if self.qdcount is None:
            self.qdcount = int(len(self.qd)) if self.qd else 0
        if self.ancount is None:
            self.ancount = int(len(self.an)) if self.an else 0
        if self.nscount is None:
            self.nscount = int(len(self.ns)) if self.ns else 0
        if self.arcount is None:
            self.arcount = int(len(self.ar)) if self.ar else 0
