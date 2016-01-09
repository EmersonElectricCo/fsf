#!/usr/bin/python
#
# Author: Jason Batchelor
# Description: Unpack CAB using cabextract as a helper.
# Basically returns a stream of all the uncompressed contents,
# multiple files are lumped together for displacement by other modules.
# Date: 12/02/2015
# Reference: http://download.microsoft.com/download/5/0/1/501ED102-E53F-4CE0-AA6B-B0F93629DDC6/Exchange/[MS-CAB].pdf
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
import os
import subprocess
from datetime import datetime as dt
from tempfile import mkstemp
from distutils.spawn import find_executable
from struct import pack, unpack
from collections import OrderedDict

def get_flag_enums(value):

   db = {}
   db['cfhdrPREV_CABINET'] = True if value == 0x1 else False
   db['cfhdrNEXT_CABINET'] = True if value == 0x2 else False
   db['cfhdrRESERVE_PRESENT'] = True if value == 0x4 else False
   return db

def get_compression_type(value):

   if value == 0x0: return 'None'
   if value == 0x1: return 'MSZIP'
   if value == 0x2: return 'QUANTUM'
   if value == 0x3: return 'LZX'
   return 'Unknown'

def last_modified(date, time):

   year = (date >> 9) + 1980
   month = (date >> 5) & 0xf
   day = date & 0x1f
   hour = time >> 11
   minute = (time >> 5) & 0x3f
   second = (time << 1) & 0x3e
   return dt(year, month, day, hour, minute, second).__str__()

def get_attributes(attribs):

   attributes = []
   if attribs & 0x1: attributes.append('Read-only file')
   if attribs & 0x2: attributes.append('Hidden file')
   if attribs & 0x4: attributes.append('System file')
   if attribs & 0x20: attributes.append('Modified since last backup')
   if attribs & 0x40: attributes.append('Run after extraction')
   if attribs & 0x80: attributes.append('Name contains UTF')
   return attributes

# Use cabextract as a helper to get the data from various MS compression formats
def collect_cab(cabname, tmpfile):

   cabextract_location = find_executable('cabextract')
   args = [cabextract_location, '-F', cabname, '-p', tmpfile]

   proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

   decompressed = proc.stdout.read()
   proc.communicate()

   # CAB will return 0 if successful
   if proc.returncode:
      s.dbg_h.error('%s There was a problem getting data from the cab file...' % dt.now())

   return decompressed

def parse_cab(buff, tmpfile):

   # CFHEADER structure
   magic = buff[0:4]
   reserved1 = buff[4:8]
   cbCabinet = unpack('<L', buff[8:12])[0]
   reserved2 = buff[12:16]
   coffFiles = unpack('<L', buff[16:20])[0]
   reserved3 = buff[20:24]
   versionMinor = ord(buff[24])
   versionMajor = ord(buff[25])
   cFolders = unpack('<H', buff[26:28])[0]
   cFiles = unpack('<H', buff[28:30])[0]
   flags = get_flag_enums(unpack('<H', buff[30:32])[0])
   setID = unpack('<H', buff[32:34])[0]
   iCabinet = unpack('<H', buff[34:36])[0]

   # Optional fields of CFHEADER depending on flags field settings
   cbCFHeader = unpack('<H', buff[36:38])[0] if flags['cfhdrRESERVE_PRESENT'] else 0
   cbCFFolder = ord(buff[39]) if flags['cfhdrRESERVE_PRESENT'] else 0
   cbCFData = ord(buff[40]) if flags['cfhdrRESERVE_PRESENT'] else 0

   # Track offset due to optional/variable fields - end of CFHEADER structure
   offset = 40 if flags['cfhdrRESERVE_PRESENT'] else 36

   if flags['cfhdrRESERVE_PRESENT'] and cbCFHeader != 0:
      abReserve = buff[offset:offset+cbCFHeader]
      offset += cbCFHeader

   if flags['cfhdrPREV_CABINET']:
      # CabinetPrev
      str_end = buff[offset:].index('\x00')
      szCabinetPrev = buff[offset:offset+str_end]
      offset += str_end+1
      # DiskPrev
      str_end = buff[offset:].index('\x00')
      szDiskPrev = buff[offset:offset+str_end]
      offset += str_end+1

   if flags['cfhdrNEXT_CABINET']:
      # CabinetNext
      str_end = buff[offset:].index('\x00')
      szCabinetNext = buff[offset:offset+str_end]
      offset += str_end+1
      # DiskNext
      str_end = buff[offset:].index('\x00')
      szDiskNext = buff[offset:offset+str_end]
      offset += str_end+1

   # CFFOLDER structure
   counter = 0
   compression_types = []
   while counter < cFolders:
      coffCabStart = unpack('<L', buff[offset:offset+4])[0]
      cCfData = unpack('<H', buff[offset+4:offset+6])[0]
      typeCompress = unpack('<H', buff[offset+6:offset+8])[0] & 0xf # MASK_TYPE

      offset += 8
      if flags['cfhdrRESERVE_PRESENT'] and cbCFFolder != 0:
         cffolder_abReserve = buff[offset:offset+cbCFFolder]
         offset += cbCFFolder
      
      compression_types.append(get_compression_type(typeCompress))

      counter += 1

   # Collect CFHEADER and CFFOLDER meta
   EXTRACT_CAB = OrderedDict([('ID', hex(setID)),
                              ('Version', '%s.%s' % (versionMajor, versionMinor)),
                              ('Compression Used', sorted(set(compression_types)))])

   # CFFILE structure
   counter = 0
   while counter < cFiles:
      cbFile = unpack('<L', buff[offset:offset+4])[0]
      uoffFolderStart = unpack('<L', buff[offset+4:offset+8])[0]
      iFolder = unpack('<H', buff[offset+8:offset+10])[0]
      date = unpack('<H', buff[offset+10:offset+12])[0]
      time = unpack('<H', buff[offset+12:offset+14])[0]
      attribs = unpack('<H', buff[offset+14:offset+16])[0]

      str_end = buff[offset+16:].index('\x00')
      szName = buff[offset+16:offset+16+str_end].replace('\\','/')
      offset += 16+str_end+1

      # Collect CFFILE Meta
      EXTRACT_CAB['Object_%s' % counter] = OrderedDict([('Name', szName),
                                                        ('Last Modified', last_modified(date, time)),
                                                        ('Attributes', get_attributes(attribs)),
                                                        ('Buffer', collect_cab(szName, tmpfile))])
      counter += 1

   return EXTRACT_CAB

def EXTRACT_CAB(s, buff):

   EXTRACT_CAB = {}
   # Prepare the cab file to be extracted file by file by cabextract (does the heavy lifting)
   tmpfd, tmpfile = mkstemp(suffix='.cab')
   tmpf = os.fdopen(tmpfd, 'wb')

   try:
      tmpf.write(buff)
      tmpf.close()
      EXTRACT_CAB = parse_cab(buff, tmpfile)
   finally:
      os.remove(tmpfile)

   return EXTRACT_CAB

if __name__ == '__main__':
   # For testing, s object can be None type if unused in function
   print (EXTRACT_CAB(None, sys.stdin.read()))
