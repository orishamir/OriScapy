from Sendreceive import sendreceive, send, sniff, prepareSockets
from HelperFuncs import RandShort, randomMac, RandInt, randomIpv6, generateSoliAddr
from Dns import DNS, DNSQR, DNSRR
from Ethernet import Ether
from Icmp import ICMP
from Arp import ARP
from Udp import UDP
from Ip import IP
from Ipv6 import IPv6
from Icmpv6 import ICMPv6
import conf as _conf
from Ndp import NdpPrefixInfoOption, NdpLLAddrOption, NdpMTUOption, NdpDnsOption, NDPRouterAdv, NDPRouterSol, NdpRouteInfoOption


class MyMeta(type):
    def __setattr__(self, key, value):
        if key == 'iface':
            prepareSockets(value)

    def __getattribute__(self, item):
        if item == "iface":
            return _conf.iface
        return super(type, self).__getattribute__(item)

class conf(metaclass=MyMeta):
    pass

srp1 = srp = sr = sendreceive
__all__ = ['ARP', 'IP', 'Ether', 'ICMP', 'UDP', 'DNS', 'DNSQR', 'DNSRR', 'IPv6', 'ICMPv6',
           'NdpDnsOption', 'NdpLLAddrOption', 'NdpMTUOption', 'NdpPrefixInfoOption', 'NdpRouteInfoOption',
           'NDPRouterAdv', 'NDPRouterSol',
           'RandShort', 'RandInt', 'randomMac','randomIpv6', 'generateSoliAddr',
           'send', 'sr', 'srp1', 'srp', 'conf', 'sniff', 'sendreceive']
# prepareSockets(conf.iface)
