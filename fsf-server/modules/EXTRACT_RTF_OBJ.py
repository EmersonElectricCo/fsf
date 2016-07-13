#!/usr/bin/env python
#
# Author: Jason Batchelor
# Description: Extract RTF objects
# Date: 11/12/2015
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

import os
import sys
import oletools.rtfobj as rtfobj
from tempfile import mkstemp

def EXTRACT_RTF_OBJ(s, buff):

   PARENT_RTF_OBJS = {}
   counter = 0
   tmpfd, tmpfile = mkstemp(suffix='.rtf')
   tmpf = os.fdopen(tmpfd, 'wb')

   try:
      tmpf.write(buff)
      tmpf.close()
      objs = rtfobj.rtf_iter_objects(tmpfile)

      for index, data in objs:
         CHILD_OBJ = {'Index'  : index,
                      'Buffer' : data }
         PARENT_RTF_OBJS['Object_%s' % counter] = CHILD_OBJ
         counter += 1

   finally:
      os.remove(tmpfile)

   return PARENT_RTF_OBJS

if __name__ == '__main__':
   print EXTRACT_RTF_OBJ(None, sys.stdin.read())
