#!/usr/bin/python
#
# Author: Jason Batchelor
# Company: Emerson
# Description: Return dictionary of metadata attributes from an OLE CF file
# Date: 07/29/2015
'''
   Copyright 2015 Emerson Electric Co.

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
from StringIO import StringIO
from hachoir_metadata import extractMetadata
from hachoir_parser import guessParser
from hachoir_core.stream import InputIOStream

def META_OLECF(s, buff):

   META_DICT = { }

   try:
      stream = InputIOStream(StringIO(buff))
      parser = guessParser(stream)
      meta = extractMetadata(parser)
   except:
      return META_DICT

   for data in sorted(meta):
      if data.values:
         if len(data.values) == 1:
            META_DICT['%s' % data.key] = data.values[0].text
         else:
            values = []
            for value in data.values:
               values.append(value.text)
            META_DICT['%s' % data.key] = values

   return META_DICT

if __name__ == '__main__':
   # For testing, s object can be None type if unused in function
   print META_OLECF(None, sys.stdin.read())

