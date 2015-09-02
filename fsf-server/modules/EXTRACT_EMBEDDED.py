#!/usr/bin/python
#
# Author: Jason Batchelor
# Company: Emerson
# Description: Carve embedded files and return buffer
# relies heavily on hachoir_subfile for most of the heavy
# lifting. 
# Date: 5/13/15
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
from hachoir_core.stream import StringInputStream
from hachoir_subfile.search import SearchSubfile
from collections import OrderedDict

def EXTRACT_EMBEDDED(s, buff):

   EXTRACT_FILES = {}
   CHILD_BUFF = {}
   
   stream = StringInputStream(buff)
   subfile = SearchSubfile(stream)
   subfile.loadParsers(categories=None, parser_ids=None)

   subfile.stats = {}
   subfile.next_offset = None
   counter = 0

   last_start = 0
   last_end = 0

   while subfile.current_offset < subfile.size:
      subfile.datarate.update(subfile.current_offset)
      for offset, parser in subfile.findMagic(subfile.current_offset):
         # Don't care about extracting the base file, just what's within it
         # False positives often return sizes exceeding the size of the file
         # they also may not even posess a content size at all, weed em out
         if offset != 0 and parser.content_size != subfile.size \
         and parser.content_size < subfile.size and parser.content_size:
            start = offset//8
            end = start + parser.content_size//8
            # We want to make sure we aren't pulling sub files out of ones 
            # we are already extracting, we will be doing that later anyway
            # when the module is run again on the 'buffer' returned key value
            if start >= last_end:
               EXTRACT_FILES['Object_%s' % counter] = OrderedDict([('Start', '%s bytes' % start),
                                                                   ('End', '%s bytes' % end),
                                                                   ('Description', parser.description),
                                                                   ('Buffer',  buff[start:end])])
               counter += 1
               last_start = start
               last_end = end

      subfile.current_offset += subfile.slice_size
      if subfile.next_offset:
         subfile.current_offset = max(subfile.current_offset, subfile.next_offset)
      subfile.current_offset = min(subfile.current_offset, subfile.size)

   return EXTRACT_FILES

if __name__ == '__main__':
   # For testing, s object can be None type if unused in function
   print EXTRACT_EMBEDDED(None, sys.stdin.read())
