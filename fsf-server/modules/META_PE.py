#!/usr/bin/python
#
# Author: Jason Batchelor
# Company: Emerson
# Description: Extract metadata associated with executable filetypes
# Date: 01/02/2015
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
import pefile
import time
from collections import OrderedDict

def enum_resources(id):
# Reference: http://msdn.microsoft.com/en-us/library/ms648009%28v=vs.85%29.aspx
   type = ''

   if id == 9: type = "RT_ACCELERATOR"
   if id == 21: type = "RT_ANICURSOR"
   if id == 22: type = "RT_ANIICON"
   if id == 2: type = "RT_BITMAP"
   if id == 1: type = "RT_CURSOR"
   if id == 5: type = "RT_DIALOG"
   if id == 17: type = "RT_DLGINCLUDE"
   if id == 8: type = "RT_FONT"
   if id == 7: type = "RT_FONTDIR"
   if id == 12: type = "RT_GROUP_CURSOR"
   if id == 14: type = "RT_GROUP_ICON"
   if id == 23: type = "RT_HTML"
   if id == 3: type = "RT_ICON"
   if id == 24: type = "RT_MANIFEST"
   if id == 4: type = "RT_MENU"
   if id == 11: type = "RT_MESSAGETABLE"
   if id == 19: type = "RT_PLUGPLAY"
   if id == 10: type = "RT_RCDATA"
   if id == 6: type = "RT_STRING"
   if id == 16: type = "RT_VERSION"
   if id == 20: type = "RT_VXD"

   return type


def get_image_hdr_characteristics(pe):

   myChars = pe.FILE_HEADER.Characteristics

   HDR_CHARS = {}

   # Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx
   IMAGE_FILE_EXECUTABLE_IMAGE = 0x2
   IMAGE_FILE_SYSTEM = 0x1000
   IMAGE_FILE_DLL = 0x2000

   HDR_CHARS['EXE'] = 'True' if myChars & IMAGE_FILE_EXECUTABLE_IMAGE else 'False'
   HDR_CHARS['SYSTEM'] = 'True' if myChars & IMAGE_FILE_SYSTEM else 'False'
   HDR_CHARS['DLL'] = 'True' if myChars & IMAGE_FILE_DLL else 'False'

   return HDR_CHARS

def get_crc(pe):

   crc = []
   crc.append('Claimed: 0x%x' % pe.OPTIONAL_HEADER.CheckSum)
   crc.append('Actual: 0x%x' % pe.generate_checksum())

   return crc

def get_machine(pe):

   # Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx
   IMAGE_FILE_MACHINE_I386 = 0x014c
   IMAGE_FILE_MACHINE_IA64 = 0x0200
   IMAGE_FILE_MACHINE_AMD64 = 0x8664

   machine = pe.FILE_HEADER.Machine

   if machine & IMAGE_FILE_MACHINE_I386:
      return 'x86'

   if machine & IMAGE_FILE_MACHINE_IA64:
      return 'Intel Itanium'

   if machine & IMAGE_FILE_MACHINE_AMD64:
      return 'x64'

   return 'Unknown'

def get_sections(pe):

   sections = []
   for section in pe.sections:
      name = section.Name.strip('\0')
      sections.append(name.decode('ascii', 'ignore'))
   return sections

def get_dllcharacteristics(pe):

   myChars = pe.OPTIONAL_HEADER.DllCharacteristics

   DLL_CHARS = {}

   # Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
   DYNAMICBASE_FLAG = 0x0040
   NXCOMPAT_FLAG = 0x0100
   NO_SEH_FLAG = 0x0400
   WDM_DRIVER = 0x2000
   NO_ISOLATION = 0x200
   FORCE_INTEGRITY = 0x80
   TERMINAL_SERVER_AWARE = 0x8000

   DLL_CHARS['ASLR'] = 'Enabled' if myChars & DYNAMICBASE_FLAG else 'Disabled'
   DLL_CHARS['DEP'] = 'Enabled' if myChars & NXCOMPAT_FLAG else 'Disabled'
   DLL_CHARS['SEH'] = 'Disabled' if myChars & NO_SEH_FLAG else 'Enabled'
   DLL_CHARS['WDM_DRIVER'] = 'Enabled' if myChars & WDM_DRIVER else 'Disabled'
   DLL_CHARS['NO_ISOLATION'] = 'Enabled' if myChars & NO_ISOLATION else 'Disabled'
   DLL_CHARS['FORCE_INTEGRITY'] = 'Enabled' if myChars & FORCE_INTEGRITY else 'Disabled'
   DLL_CHARS['TERMINAL_SERVER_AWARE'] = 'Enabled' if myChars & TERMINAL_SERVER_AWARE else 'Disabled'

   return DLL_CHARS

def get_resource_names(pe):

   try: 
      pe.DIRECTORY_ENTRY_RESOURCE.entries
   except:
      return 'None'

   resource_names = []
   for res in pe.DIRECTORY_ENTRY_RESOURCE.entries:
      if res.name is not None:
         resource_names.append(res.name.__str__())
   return resource_names

def get_resource_types(pe):

   try:
      pe.DIRECTORY_ENTRY_RESOURCE.entries
   except:
      return 'None'

   resource_types = []
   for res in pe.DIRECTORY_ENTRY_RESOURCE.entries:
      if res.id is not None:
         resource_types.append(enum_resources(res.id))
   return resource_types

def get_exports(pe):

   my_exports = []

   try:
      pe.DIRECTORY_ENTRY_EXPORT.symbols
   except:
      return 'None'

   for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
      my_exports.append(exp.name)

   return my_exports

def get_imports(pe):

   IMPORTS = {}

   try:
      pe.DIRECTORY_ENTRY_IMPORT
   except:
      return 'None'

   for entry in pe.DIRECTORY_ENTRY_IMPORT:
      my_imports = []
      for imp in entry.imports:
         my_imports.append(imp.name)
      IMPORTS['%s' % entry.dll] = my_imports

   return IMPORTS

def get_stringfileinfo(pe):

   STRINGFILEINFO = {}

   try:
      pe.FileInfo
   except:
      return 'None'

   for fi in pe.FileInfo:
      if fi.Key == 'StringFileInfo':
         for st in fi.StringTable:
            for entry in st.entries.items():
               k = entry[0].encode('ascii','backslashreplace')
               v = entry[1].encode('ascii','backslashreplace')
               STRINGFILEINFO['%s' % k] = v   

   return STRINGFILEINFO

def META_PE(s, buff):

   pe = pefile.PE(data=buff)

   META_PE = OrderedDict([('File Type', get_image_hdr_characteristics(pe)),
                         ('CRC', get_crc(pe)),
                        ('Compiled', '%s UTC' % time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp))),
                        ('Architecture', get_machine(pe)),
                        ('EntryPoint', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)),
                        ('ImageBase', hex(pe.OPTIONAL_HEADER.ImageBase)),
                        ('Characteristics', get_dllcharacteristics(pe)),
                        ('Sections', get_sections(pe)),
                        ('Resource Names', get_resource_names(pe)),
                        ('Resource Types', get_resource_types(pe)),
                        ('Exports', get_exports(pe)),
                        ('Imports', get_imports(pe)),
                        ('Import Hash', pe.get_imphash()),
                        ('StringFileInfo', get_stringfileinfo(pe))])

   return META_PE

if __name__ == '__main__':
   print META_PE(None, sys.stdin.read())
