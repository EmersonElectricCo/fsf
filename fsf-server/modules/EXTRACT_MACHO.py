import sys
from macholibre import macholibre
from StringIO import StringIO


def EXTRACT_MACHO(s, buff):
        dictionary = macholibre.parse(StringIO(buff))

        return dictionary



if __name__ == '__main__':
    print(EXTRACT_MACHO(None, sys.stdin.read()))