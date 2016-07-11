#!/usr/bin/env python
#
# Jason Batchelor
# Module used to scan files against our Yara signatures
# 04/21/2015
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
import yara

def SCAN_YARA(s, buff):

   rules = yara.compile(s.yara_rule_path)

   results = { }
   if rules:
      matches = rules.match(data=buff)
      if matches:
         for m in matches:
            if m.meta:
               results['%s' % m.rule] = m.meta
            else:
               results['%s' % m.rule] = 'No Meta Provided'
   return results
