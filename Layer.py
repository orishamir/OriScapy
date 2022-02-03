from abc import ABCMeta, abstractmethod
from colorama import init, Fore, Style
RST = Style.RESET_ALL
init()

class Layer(metaclass=ABCMeta):
    def __truediv__(self, other):
        if hasattr(self, 'data'):
            self.data = self.data / other
        else:
            self.data = other
        return self

    def __rtruediv__(self, other):
        self.data = other
        return self

    def __itruediv__(self, other):
        return self / other

    def __str__(self):
        #self._autocomplete()
        ret =  f"     {Fore.LIGHTRED_EX}\033[1m[{self.__class__.__name__}]{RST}     \n"

        all_attr = self.__dict__
        for key, val in all_attr.items():
            if key == 'data':
                continue
            if key in ("lladdr", ):
                continue

            if 'port' not in key and key != 'ttl' and key not in ['qd', 'an', 'ns', 'ar'] and val not in (0,1) and isinstance(val, int):
                val = hex(val)

            if key in ('qd', 'an') and val:
                ret += f"       {Fore.MAGENTA}{key}{RST}="
                for dnsr in val:
                    dnsr = f'\n{" "*12}'.join(str(dnsr).split('\n'))
                    ret += f"       {Fore.LIGHTGREEN_EX} {dnsr}{RST}\n"
            elif key == '_options':
                ret += f"       {Fore.MAGENTA}options{RST}="
            else:
                ret += f"       {Fore.MAGENTA}{key:<15} {RST}={Fore.LIGHTGREEN_EX} {val}{RST}\n"

        if (hasattr(self, 'data') and not isinstance(self.data, bytes) and self.data is not None) or (hasattr(self, '_options') and self._options):
            ret += '\n'
            if hasattr(self, 'data'):
                s = str(self.data)
            elif hasattr(self, '_options'):
                s = ''
                for opt in self._options:
                    s += f"{opt}\n"

            s = [f"    {i}" for i in s.splitlines()]
            ret += '\n    '.join(s)
        return ret

    def __contains__(self, item):
        if isinstance(self, item):
            return True
        if not hasattr(self, 'data'):
            return False
        if isinstance(self.data, bytes):
            return False
        return item in self.data

    def __getitem__(self, item):
        if item not in self:
            raise KeyError(f"{item.__name__} does not exist.")
        if isinstance(self, item):
            return self
        return self.data[item]

    def __getattr__(self, name):
        """
        Custom functionality of pkt.attr, so for example
        IP attributes are accessible from Ether layer forward
        :param name: str
        :return:
        """
        if name in self.__dict__:
            return self.__dict__[name]
        if 'data' not in self.__dict__:
            raise AttributeError(f"No attribute {name}")
        return getattr(self.data, name)

    @abstractmethod
    def __len__(self):
        # return len(bytes(self))
        pass

    def _autocomplete(self):
        pass


    def __bytes__(self):
        return