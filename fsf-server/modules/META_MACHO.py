#!/usr/bin/env python
#
# Author: Jamie Ford
# Description: Parses mach-o files using the Macholibre library by Aaron Stevens
# Returns various metadata about the file
# Date: 09/08/2016
'''
   Copyright 2016 BroEZ

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''
import sys
from macholibre import macholibre

import os
from tempfile import mkstemp

def META_MACHO(s, buff):
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

    # META_BASIC_INFO already hs this informaton
    if dictionary.has_key('hashes'):
        dictionary.pop('hashes')
    if dictionary.has_key('size'):
        dictionary.pop('size')
    dictionary['architecutures'] = []


    #Macholibre either has macho or universal
    if dictionary.has_key('macho'):
        popMachoKeys(dictionary['macho'])
        dictionary['Universal'] = False
        macho = dictionary.pop('macho')
        #I need it twice so there's no point in searching

        # Makes the key Macho + the cputype from the macho dictionary, if it has that key. Also replaces spaces with '_'
        machoKey = "macho_" + macho['cputype'].replace(' ', '_') if macho.has_key('cputype') else 'macho'
        dictionary['machos'] = [{machoKey: macho}]
        dictionary['architecutures'].append(macho['subtype'] if macho.has_key('subtype') else '')

        del macho, machoKey

    elif dictionary.has_key('universal'):
        #Universal has embedded machos
        if dictionary['universal'].has_key('machos'):
            dictionary['Universal'] = True
            dictionary['machos'] = []

            for index, macho in enumerate(dictionary['universal']['machos']):
                popMachoKeys(macho)
                hasCPU = macho.has_key('cputype')
                # Does the same thing but make sure not to overwrite the indexes if neither has 'cputype' as a key
                machoKey = "macho_" + macho['cputype'].replace(' ', '_') if hasCPU else 'macho_' + str(index)
                if macho.has_key('subtype'):
                    dictionary['architecutures'].append(macho['subtype'])
                dictionary['machos'].append({machoKey: macho})
            dictionary.pop('universal')



    return dictionary

def popMachoKeys(macho):
    #Keys to keep to prevent too much printout (These can be added and removed by just adding them to the list)
    keepKeys = ['filetype', 'signature', 'flags', 'offset', 'cputype', 'minos', 'dylibs', 'subtype']
    for key in macho.keys():
        if (key not in keepKeys):
            macho.pop(key)


if __name__ == '__main__':
    print(META_MACHO(None, sys.stdin.read()))
