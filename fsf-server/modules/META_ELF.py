#!/usr/bin/env python
#
# Author: Jason Batchelor
# Company: Emerson
# Description: Extract metadata associated with ELF payloads
# Date: 01/26/2016
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
from StringIO import StringIO
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

import pprint

def get_die_entries(elffile):
   die_entries = []

   # Get name of Debug Info Entries (DIE)
   if elffile.has_dwarf_info():
      dwarfinfo = elffile.get_dwarf_info()

      for cu in dwarfinfo.iter_CUs():
         die_entries.append(cu.get_top_DIE().get_full_path())
   
   return die_entries

def get_section_names(elffile):
   section_names = []
   symbol_names = []

   for section in elffile.iter_sections():

      # Get names of all sections in ELF file
      if len(section.name) > 0:
         section_names.append(section.name)

      # If symbol tables exist for the section, take inventory
      if isinstance(section, SymbolTableSection):
         for i in range(0, section.num_symbols()):
            if len(section.get_symbol(i).name) > 0:
               symbol_names.append(section.get_symbol(i).name)

   return section_names, symbol_names

def META_ELF(s, buff):
   elffile = ELFFile(StringIO(buff))

   META_ELF = { 'Arch' : elffile.get_machine_arch(),
                'Debug Entries' : get_die_entries(elffile) }

   META_ELF['Section Names'], META_ELF['Symbol Names'] = get_section_names(elffile)  

   return META_ELF

if __name__ == '__main__':
   pprint.pprint(META_ELF(None, sys.stdin.read()))
