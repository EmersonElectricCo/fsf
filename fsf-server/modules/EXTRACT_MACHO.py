import sys
from macholibre import macholibre
from StringIO import StringIO
import os
from tempfile import mkstemp

def EXTRACT_MACHO(s, buff):
    tmpfd, tmpfile = mkstemp()
    tmpf = os.fdopen(tmpfd, 'wb')

    try:
        #Writing the buffer to a temp file
        tmpf.write(buff)
        tmpf.close()
        dictionary = macholibre.parse(tmpfile)
    finally:
        #Remove it to save space
        os.remove(tmpfile)
    if dictionary.has_key('name'):
        #The name doesn't make sense with the temp file
        dictionary.pop('name')
    #Macholibre either has macho or universal
    if dictionary.has_key('macho'):
        popMachoKeys(dictionary['macho'])
    elif dictionary.has_key('universal'):
        #Universal has embedded machos
        if dictionary['universal'].has_key('machos'):
            for macho in dictionary['universal']['machos']:
                popMachoKeys(macho)


    return dictionary

def popMachoKeys(macho):
    #Keys to keep to prevent too much printout
    keepKeys = ['filetype', 'signature', 'flags', 'offset', 'cputtype', 'minos', 'size', 'dylibs']
    for key in macho.keys():
        if (key not in keepKeys):
            macho.pop(key)


if __name__ == '__main__':
    print(EXTRACT_MACHO(None, sys.stdin.read()))
