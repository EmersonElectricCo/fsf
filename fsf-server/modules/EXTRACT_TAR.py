#!/usr/bin/env python
#
# Author: Jason Batchelor
# Description: Extract files from TAR archive file
# Date: 11/16/2015
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
import tarfile
from datetime import datetime
from StringIO import StringIO
from collections import OrderedDict

# For security reasons, we will only allow our module to process a max of twenty identified files
MAX_FILES = 20

def get_tar_type(ti):

   type = 'Unknown'

   if ti.isfile(): type = 'File'
   elif ti.isdir(): type = 'Directory'
   elif ti.issym(): type = 'Sym Link'
   elif ti.islnk(): type = 'Hard Link'
   elif ischr(): type = 'Character device'
   elif isblk(): type = 'Block device' 
   elif isfifo(): type = 'FIFO'
   
   return type

def EXTRACT_TAR(s, buff):

   EXTRACT_TAR = {}
   file_num = 0

   tarf = tarfile.TarFile(fileobj=StringIO(buff), mode='r')

   for ti in tarf:

      if file_num >= MAX_FILES:
         tarf.close()
         EXTRACT_TAR['Object_%s' % file_num] = { 'Error' : 'Max number of archived files reached' }
         return EXTRACT_TAR

      CHILD_TAR = OrderedDict([('Name', ti.name),
                               ('Last modified', datetime.fromtimestamp(ti.mtime).strftime("%Y-%m-%d %H:%M:%S")),
                               ('Type', get_tar_type(ti)),
                               ('UID', ti.uid ),
                               ('GID', ti.gid ),
                               ('Username', ti.uname),
                               ('Groupname', ti.gname)])

      if ti.isfile():

         try:
            f = tarf.extractfile(ti)
            CHILD_TAR['Buffer'] = f.read()
            f.close()
         except:
            CHILD_TAR['Buffer'] = 'Failed to extract this specific archive. Invalid or corrupt?'

      EXTRACT_TAR['Object_%s' % file_num] = CHILD_TAR
   
      file_num += 1

   tarf.close()

   return EXTRACT_TAR

if __name__ == '__main__':
   print EXTRACT_TAR(None, sys.stdin.read())
