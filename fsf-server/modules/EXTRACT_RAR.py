#!/usr/bin/python
#
# Author: Jason Batchelor
# Company: Emerson
# Description: Extract RAR files and get metadata
# Date: 05/19/2015
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
import shutil
import rarfile
import os
from tempfile import mkstemp
from datetime import datetime
from collections import OrderedDict

def get_compression_method(field_value):

   map_val = 'Unknown'

   # Enum list from: http://forensicswiki.org/wiki/RAR
   if field_value == 0x30: map_val = 'Storing'
   elif field_value == 0x31: map_val = 'Fastest Compression'
   elif field_value == 0x32: map_val = 'Fast Compression'
   elif field_value == 0x33: map_val = 'Normal Compression'
   elif field_value == 0x34: map_val = 'Good Compression'
   elif field_value == 0x35: map_val = 'Best Compression'

   return map_val

def get_system_mapping(field_value):

   map_val = 'Unknown'

   # Enum list from: http://forensicswiki.org/wiki/RAR
   if field_value == 0: map_val = 'MS-DOS'
   elif field_value == 1: map_val = 'OS/2'
   elif field_value == 2: map_val = 'Windows'
   elif field_value == 3: map_val = 'UNIX'
   elif field_value == 4: map_val = 'Macintosh'
   elif field_value == 5: map_val = 'BeOS'

   return map_val

def get_rar_info(tmpfile, PARENT_BIN):

   file_num = 0
   password_required = False

   rf = rarfile.RarFile(tmpfile)

   if rf.needs_password():
      password_required = True

   for r in rf.infolist():
      CHILD_BIN = OrderedDict([('Filename', r.filename),
                               ('Last Modified', datetime(*r.date_time).strftime("%Y-%m-%d %H:%M:%S")),
                               ('Comment', r.comment),
                               ('CRC', hex(r.CRC)),
                               ('Compressed Size', '%s bytes' % r.compress_size),
                               ('Uncompressed Size', '%s bytes' % r.file_size),
                               ('Compress Type', get_compression_method(r.compress_type)),
                               ('Create System', get_system_mapping(r.host_os)),
                               ('Password Required', password_required)])

      if not password_required and r.file_size != 0:
         CHILD_BIN['Buffer'] = rf.read(r)

      PARENT_BIN['Object_%s' % file_num] = CHILD_BIN
      file_num += 1

   rf.close()

   return PARENT_BIN

def EXTRACT_RAR(s, buff):

   EXTRACT_RAR = { }
   tmpfd, tmpfile = mkstemp(suffix='.rar')
   tmpf = os.fdopen(tmpfd, 'wb')

   try:
      tmpf.write(buff)
      tmpf.close()
      EXTRACT_RAR = get_rar_info(tmpfile, EXTRACT_RAR)
   finally:
      os.remove(tmpfile)

   return EXTRACT_RAR

if __name__ == '__main__':
   # For testing, s object can be None type if unused in function
   print EXTRACT_RAR(None, sys.stdin.read())
