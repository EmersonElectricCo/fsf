#!/usr/bin/env python
#
# Author: Jason Batchelor
# Company: Emerson
# Description: Simple module to run on zip files and return metadata as a dictionary.
# Date: 12/16/2014
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
import czipfile
from datetime import datetime
from StringIO import StringIO
from collections import OrderedDict

# For security reasons, we will only allow our module to process a max of twenty identified files
MAX_FILES = 20

def get_system_mapping(field_value):

   map_val = 'Unknown'

   # Enum list from: http://www.pkware.com/documents/casestudies/APPNOTE.TXT
   if field_value == 0: map_val = 'MS-DOS'
   elif field_value == 1: map_val = 'Amiga'
   elif field_value == 2: map_val = 'OpenVMS'
   elif field_value == 3: map_val = 'UNIX'
   elif field_value == 4: map_val = 'VM/CMS'
   elif field_value == 5: map_val = 'Atari ST'
   elif field_value == 6: map_val = 'OS/2 H.P.F.S.'
   elif field_value == 7: map_val = 'Macintosh'
   elif field_value == 8: map_val = 'Z-System'
   elif field_value == 9: map_val = 'CP/M'
   elif field_value == 10: map_val = 'Windows NTFS'
   elif field_value == 11: map_val = 'MVS (OS/390 - Z/OS)'
   elif field_value == 12: map_val = 'VSE'
   elif field_value == 13: map_val = 'Acorn Risc'
   elif field_value == 14: map_val = 'VFAT'
   elif field_value == 15: map_val = 'Alternate MVS'
   elif field_value == 16: map_val = 'BeOS'
   elif field_value == 17: map_val = 'Tandem'
   elif field_value == 18: map_val = 'OS/400'
   elif field_value == 19: map_val = 'OS X (Darwin)'

   return map_val

def get_compression_method(field_value):
   
   map_val = 'Unknown'

   # Enum list from: http://www.pkware.com/documents/casestudies/APPNOTE.TXT
   if field_value == 0: map_val = 'The file is stored (no compression)'
   elif field_value == 1: map_val = 'The file is Shrunk'
   elif field_value == 2: map_val = 'The file is Reduced with compression factor 1'
   elif field_value == 3: map_val = 'The file is Reduced with compression factor 2'
   elif field_value == 4: map_val = 'The file is Reduced with compression factor 3'
   elif field_value == 5: map_val = 'The file is Reduced with compression factor 4'
   elif field_value == 6: map_val = 'The file is Imploded'
   elif field_value == 7: map_val = 'Tokenizing compression algorithm'
   elif field_value == 8: map_val = 'Standard compression algorithm'
   elif field_value == 9: map_val = 'Enhanced Deflating using Deflate64(tm)'
   elif field_value == 10: map_val = 'PKWARE Data Compression Library Imploding (old IBM TERSE)'
   elif field_value == 12: map_val = 'File is compressed using BZIP2 algorithm'
   elif field_value == 14: map_val = 'LZMA (EFS)'
   elif field_value == 18: map_val = 'File is compressed using IBM TERSE (new)'
   elif field_value == 19: map_val = 'IBM LZ77 z Architecture (PFS)'
   elif field_value == 97: map_val = 'WavPack compressed data'
   elif field_value == 98: map_val = 'PPMd version I, Rev 1'
   
   return map_val

def EXTRACT_ZIP(s, buff):

   EXTRACT_ZIP = { }
   file_num = 0
   password_required = False

   zf = czipfile.ZipFile(StringIO(buff))

   for z in zf.namelist():

      if file_num >= MAX_FILES:
         zf.close()
         EXTRACT_ZIP['Object_%s' % file_num] = { 'Error' : 'Max number of compressed files reached' }
         return EXTRACT_ZIP

      zi_child = zf.getinfo(z)

      # Test if content is encrypted
      if zi_child.flag_bits & 0x1:
         password_required = True

      CHILD_ZIP = OrderedDict([('Name', zi_child.filename),
                             ('Last modified', datetime(*zi_child.date_time).strftime("%Y-%m-%d %H:%M:%S")),
                             ('Comment', zi_child.comment),
                             ('CRC', hex(zi_child.CRC)),
                             ('Compressed Size', '%s bytes' % zi_child.compress_size),
                             ('Uncompressed Size', '%s bytes' % zi_child.file_size),
                             ('Compress Type', get_compression_method(zi_child.compress_type)),
                             ('Create System', get_system_mapping(zi_child.create_system)),
                             ('Password Required', password_required)])

      if not password_required and zi_child.file_size != 0:

         try:
            f = zf.open(z, 'r')
            CHILD_ZIP['Buffer'] = f.read()
            f.close()
         except:
            CHILD_ZIP['Buffer'] = 'Failed to extract this specific archive. Invalid or corrupt?'

      EXTRACT_ZIP['Object_%s' % file_num] = CHILD_ZIP
   
      file_num += 1

   zf.close()

   return EXTRACT_ZIP

if __name__ == '__main__':
   # For testing, s object can be None type if unused in function
   print EXTRACT_ZIP(None, sys.stdin.read())

