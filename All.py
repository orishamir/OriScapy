from Sendreceive import sendreceive, send, prepareSockets
from HelperFuncs import RandShort
from Dns import DNS, DNSQR, DNSRR
from Ethernet import Ether
from Icmp import ICMP
from Arp import ARP
from Udp import UDP
from Ip import IP
import conf as _conf

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
__all__ = ['sendreceive', 'ARP', 'IP', 'Ether', 'ICMP', 'UDP', 'DNS', 'DNSQR', 'DNSRR', 'RandShort', 'send', 'sr', 'conf']
