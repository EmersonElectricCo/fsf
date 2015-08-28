#!/usr/bin/python
#
# Author: Jason Batchelor
# Company: Emerson
# Description: Show metadata from parsing OOXML core properties files
# Date: 5/5/2015
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
import xmltodict

def META_OOXML(s, buff):

   CORE_PROP = xmltodict.parse(buff)

   # We don't care about keys for XML namespaces
   xmlns = "@xmlns"

   try:
      for key, child_dict in CORE_PROP.items():
         for k, v in child_dict.items():
            if xmlns in k:
               del child_dict[k]
               continue

            if 'dcterms:' in k:
               child_dict[k[k.index(':')+1:]] = child_dict[k]['#text']
               del child_dict[k]
               continue

            if 'cp:' in k or 'dc:' in k:
               child_dict[k[k.index(':')+1:]] = v
               del child_dict[k]

   except:
      pass

   return CORE_PROP

if __name__ == '__main__':
   # For testing, s object can be None type if unused in function
   print META_OOXML(None, sys.stdin.read())

