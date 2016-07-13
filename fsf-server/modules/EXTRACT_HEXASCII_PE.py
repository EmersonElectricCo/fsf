#!/usr/bin/env python
#
# Author: Jason Batchelor
# Description: Binary convert on hexascii printables contained within a stream 
# believed to represent an executable file.
# Date: 03/07/2016
'''
   Copyright 2016 Carnegie Mellon University

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
import re
import binascii

def EXTRACT_HEXASCII_PE(s, buff):
   # Function must return a dictionary
   SUB_OBJ = {}
   counter = 0

   for m in re.finditer(r"4[dD]5[aA][0-9A-Fa-f]+", buff):
      SUB_OBJ.update( { 'Object_%s' % counter : { 'Buffer' : binascii.unhexlify(m.group(0)) } } ) 
      counter += 1

   return SUB_OBJ

if __name__ == '__main__':
   # For testing, s object can be None type if unused in function
   print EXTRACT_HEXASCII_PE(None, sys.stdin.read())
