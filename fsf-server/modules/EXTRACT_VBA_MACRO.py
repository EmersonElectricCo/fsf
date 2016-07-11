#!/usr/bin/env python
#
# Author: Jason Batchelor
# Description: Extract metadata for Office documents
# Date: 02/01/2016
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
import itertools
import operator
import logging
from collections import OrderedDict
from oletools.olevba import VBA_Parser, VBA_Scanner

def scan_macro(vba_code):
   
   SCAN = {}

   vba_scanner = VBA_Scanner(vba_code)
   results = vba_scanner.scan(include_decoded_strings=False)
   for key, subiter in itertools.groupby(results, operator.itemgetter(0)):
      groups = []
      groups.extend(['%s: %s' % (desc[1], desc[2]) for desc in subiter])
      SCAN['%s' % key] = groups

   if not SCAN:
      return 'No results from scan'

   return SCAN

def EXTRACT_VBA_MACRO(s, buff):

   EXTRACT_MACRO = {}
   counter = 0

   ### TODO: REMOVE THIS WORKAROUND ONCE MODULE AUTHOR FIXES CODE ###
   ### Reference: http://stackoverflow.com/questions/32261679/strange-issue-using-logging-module-in-python/32264445#32264445
   ### Reference: https://bitbucket.org/decalage/oletools/issues/26/use-of-logger
   ### /dev/null used instead of NullHandler for 2.6 compatibility 
   logging.getLogger('workaround').root.addHandler(logging.FileHandler('/dev/null'))
   ###

   vba = VBA_Parser('None', data=buff)

   if not vba.detect_vba_macros():
      return EXTRACT_MACRO

   for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():

      CHILD_MACRO = OrderedDict([('OLE Stream', stream_path),
                                 ('VBA Filename', vba_filename.decode('ascii', 'ignore')),
                                 ('Scan', scan_macro(vba_code)),
                                 ('Buffer', vba_code)])

      EXTRACT_MACRO['Object_%s' % counter] = CHILD_MACRO
      counter += 1

   return EXTRACT_MACRO
   
if __name__ == '__main__':
   print EXTRACT_VBA_MACRO(None, sys.stdin.read())
