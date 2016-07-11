#!/usr/bin/env python
#
# Author: Jason Batchelor
# Company: Emerson
# Description: Get metadata from PDF and return dict of metadata
# Date: 12/30/2014
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
from PyPDF2 import PdfFileReader
from StringIO import StringIO

def META_PDF(s, buff):

   META_PDF = { }
   pdfinfo = PdfFileReader(StringIO(buff)).documentInfo

   for i in pdfinfo:
      META_PDF['%s' % i] = pdfinfo[i]

   return META_PDF

