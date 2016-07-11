#!/usr/bin/env python
#
# Author: Jason Batchelor
# Description: Process compressed SWF files
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
import zlib
import pylzma

def EXTRACT_SWF(s, buff):

   SWF = {}

   magic = buff[:3]
   data = ''

   if magic == 'CWS':
      SWF['Buffer'] = 'FWS' + buff[3:8] + zlib.decompress(buff[8:])
   elif magic == 'ZWS':
      SWF['Buffer'] = 'FWS' + buff[3:8] + pylzma.decompress(buff[12:])
   elif magic == 'FWS':
      SWF['Version'] = ord(buff[3])

   return SWF

if __name__ == '__main__':
   # For testing, s object can be None type if unused in function
   print EXTRACT_SWF(None, sys.stdin.read())

