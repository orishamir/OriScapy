from colorama import Fore
from Layer import Layer


class Raw(Layer):
    load = None

    def __init__(self, load=None):
        self.comment = Fore.LIGHTBLACK_EX+"\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\bSince the incompleteness of this package, this is \n"+' '*7+\
                       "either part of the previous layer or a layer itself, \n" +' '*7+\
                       "and may not be auto detected as an existing layer. \n"
        self.load = load

    def __bytes__(self):
        self._autocomplete()
        return bytes(self.load)

    def _autocomplete(self):
        if self.load is None:
            self.load = b''