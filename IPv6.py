from Layer import Layer

# https://datatracker.ietf.org/doc/html/rfc2460#section-3

class IPv6(Layer):
    version = None
    traffic_class = None
    flow_label = None
    payload_length = None
    protocol = None
    hoplimit = None
    psrc = None
    pdst = None

    def __init__(self, psrc=None, pdst=None):
        self.psrc = psrc
        self.pdst = pdst

    def __bytes__(self):
        self._autocomplete()

    def _autocomplete(self):
        if self.version is None:
            self.version = 6
