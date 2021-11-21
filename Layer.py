from colorama import init, Fore, Style
RST = Style.RESET_ALL
init()

class Layer:
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
            if 'port' not in key and key != 'ttl' and val not in [0,1] and isinstance(val, int):
                val = hex(val)
            if key in ('qd', 'an') and val:
                ret += f"       {Fore.MAGENTA}{key}{RST}="
                #print(val)
                for dnsr in val:
                    dnsr = f'\n{" "*12}'.join(str(dnsr).split('\n'))
                    ret += f"       {Fore.LIGHTGREEN_EX} {dnsr}{RST}\n"
            else:
                ret += f"       {Fore.MAGENTA}{key:<15} {RST}={Fore.LIGHTGREEN_EX} {val}{RST}\n"

        if hasattr(self, 'data') and not isinstance(self.data, bytes) and self.data is not None:
            ret += '\n'
            s = str(self.data)
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
        if isinstance(item, int):
            raise KeyError
        if item not in self:
            raise KeyError(f"{item.__name__} does not exist.")
        if isinstance(self, item):
            return self
        return self.data[item]

    def _autocomplete(self):
        pass

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        return