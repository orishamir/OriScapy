from Layer import Layer

# https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol
# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6
# https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol

class ICMPv6(Layer):
    # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6#Types
    class Types:
        dst_unreachable = 1
        time_exceeded = 3
        req = 128
        reply = 129
        router_soli = 133
        router_adv = 134
        neighbor_soli = 135
        neighbor_adv = 136
        redirect_msg = 137

    type = None
    code = None
    chksum = None

    def __init__(self, type=None, code=None, chksum=None):
        self.type = type
        self.code = code
        self.chksum = chksum
