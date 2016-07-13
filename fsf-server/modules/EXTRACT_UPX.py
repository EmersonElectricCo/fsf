#!/usr/bin/env python
#
# Author: Jason Batchelor
# Description: Unpack UPX packed binaries
# Date: 8/28/2015
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
import os
import subprocess
from datetime import datetime as dt
from tempfile import mkstemp
from distutils.spawn import find_executable

def EXTRACT_UPX(s, buff):

   UNPACKED = {}
   tmpfd, tmpfile = mkstemp(suffix='.upx')
   tmpf = os.fdopen(tmpfd, 'wb')

   upx_location = find_executable("upx")
   outfile = tmpfile + ".out"
   args = [upx_location, "-q", "-d", tmpfile, "-o", outfile]

   try:
      tmpf.write(buff)
      tmpf.close()

      proc = subprocess.Popen(args, stdout=subprocess.PIPE, 
                              stderr=subprocess.STDOUT)

      proc.communicate()
      # UPX will return 0 if successful
      if not proc.returncode:
         f = open(outfile, 'rb')
         UNPACKED['Buffer'] = f.read()
         f.close()
      else:
         s.dbg_h.error('%s There was a problem unpacking the file...' % dt.now())
         raise ValueError()
   finally:
      os.remove(tmpfile)
      os.remove(outfile)

   return UNPACKED

if __name__ == '__main__':
   # For testing, s object can be None type if unused in function
   print EXTRACT_UPX(None, sys.stdin.read())
