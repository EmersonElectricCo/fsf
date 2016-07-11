#!/usr/bin/env python
#
# Author: Jason Batchelor
# Company: Emerson
# Description: Module that is applied to all files being scanned. Generate core metadata.
# Date: 12/10/2015
'''
   Copyright 2016 Emerson Electric Co.

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
import hashlib
import ssdeep
from collections import OrderedDict

def META_BASIC_INFO(s, buff):

   BASIC_INFO = OrderedDict([('MD5', hashlib.md5(buff).hexdigest()),
                           ('SHA1', hashlib.sha1(buff).hexdigest()),
                           ('SHA256', hashlib.sha256(buff).hexdigest()),
                           ('SHA512', hashlib.sha512(buff).hexdigest()),
                           ('ssdeep' , ssdeep.hash(buff)),
                           ('Size', '%s bytes' % len(buff))])

   return BASIC_INFO

if __name__ == '__main__':
   # For testing, s object can be None type if unused in function
   print META_BASIC_INFO(None, sys.stdin.read())
