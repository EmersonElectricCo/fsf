#!/usr/bin/env python
#
# Process objects and sub objects according to disposition criteria.
# Log all the results. 
#
# Jason Batchelor
# Emerson Corporation
# 02/09/2016
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
import logging
import signal
import json
import time
import hashlib
from datetime import datetime as dt
from collections import OrderedDict
from distutils.spawn import find_executable
from subprocess import Popen, PIPE, STDOUT
# Ensure concurrent logging
from cloghandler import ConcurrentRotatingFileHandler
# Configurations
from conf import disposition
# Custom modules 
from modules import *

# Global counter, helps keep track of object depth
COUNTER = 0

# List of modules that ran and returned results - used in summary generation
MODULES_RUN = []

# List of Yara rules that fired - used in summary generation
YARA_RULES = []

# Determine if we need to save sub object buffers
SUB_TRACKER = False

# Result: Recurse through dictionary to identify and process returned buffers.
# When complete, we update the dictionary with new module information and remove the buffer. 
def recurse_dictionary(s, myDict):

   for key, value in myDict.items():
      if isinstance(value, dict):
         recurse_dictionary(s, value)
      if key == 'Buffer':
         # Process any new buffers from a module 
         myDict.update(process_buffer(s, value))
         # Keep track of sub objects if client wants them
         if SUB_TRACKER:
            s.sub_objects.append(value)
         # We don't care to display/log the buffer after processing
         del myDict[key]
         # Multiple buffers can be found at the same depth
         # We don't want to increment depth if we are just at the same spot
         global COUNTER
         COUNTER -= 1

   return myDict

def invoke_module(s, module, buff, myDict):

   def timer(*args):

      s.dbg_h.error('%s The scanner timeout threshold has been triggered...' % dt.now())
      raise Exception()

   # Set timeout for processing of data
   signal.signal(signal.SIGALRM, timer)
   signal.alarm(s.timeout)

   m = sys.modules['modules.%s' % module]
   try:
      module_result = getattr(m, module)(s, buff)
      # Are you a dictionary?
      if isinstance(module_result, dict):
         # Do you have something for me?
         if module_result:
            myDict['%s' % module] = recurse_dictionary(s, module_result)
            MODULES_RUN.append(module)
   except:
      e = sys.exc_info()[0]
      s.dbg_h.error('%s Failed to run module %s on %s byte buffer supplied for file %s. Error: %s' \
      % (dt.now(), module, len(buff), s.filename, e))

   return myDict

# Result: Logs any scan hits on the file and sends an alert if a signature prefix match is observed
def process_buffer(s, buff):

   myDict = OrderedDict()

   global COUNTER
   COUNTER += 1

   if COUNTER >= s.max_depth:
      myDict['Error'] = 'Max depth of %s exceeded' % s.max_depth
      return myDict

   for module in disposition.default:
      myDict.update(invoke_module(s, module, buff, myDict))

   # Yara helps drive execution of modules and alerting, no Yara = nothing more to do for buffer
   if 'SCAN_YARA' not in myDict:
      return myDict

   results = myDict['SCAN_YARA'].keys()
   YARA_RULES.extend(results)

   # Are there opportunities to run modules or set alert flag?
   for rule, modules, alert in disposition.triggers:
      if rule in results and alert:
         s.alert = True

      if rule in results and modules is not None:
         for module in modules:
            myDict.update(invoke_module(s, module, buff, myDict))

   return myDict

# Result: Return post processing observations back
def post_processor(s, report):

   observations = []

   jq_location = find_executable('jq')
   if jq_location == None:
      s.dbg_h.error('%s Unable to find JQ, aborting post-processing routine...' % dt.now())
      return

   for script, observation, alert in disposition.post_processor:
      args = [jq_location, '-f', '%s/%s/%s' % (os.path.dirname(os.path.realpath(__file__)), 'jq', script)]
      proc = Popen(args, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
      results = proc.communicate(input=json.dumps(report))[0].split('\n')

      if proc.returncode:
         s.dbg_h.error('%s There was a problem executing the JSON interpreter...' % dt.now())
         return

      for r in results:
         if r == 'true':
            observations.append(observation)
            # Allow ourselves to alert on certain observations
            if alert:
               s.alert = True

            break

   return observations

# Result: copy file, return export path to user
def archive_file(s):

   path = '%s/%s' % (s.export_path, s.filename)

   try:
      with open(path, 'w') as f:
         f.write(s.file)
         f.close()
   except:
      e = sys.exc_info()[0]
      s.dbg_h.error('%s There was an error writing to the export directory. Error: %s' % (dt.now(), e))

   return path

# Result: archive file and associated sub objects, return export path to user
def archive_all(s, report):

   report_dump = json.dumps(report)
   # Generate dirname by calculating epoch time and hash of results
   dirname = '%s/fsf_dump_%s_%s' % (s.export_path, int(time.time()), hashlib.md5(report_dump).hexdigest())

   try:

      os.mkdir(dirname)

      # Archive the base file
      with open ('%s/%s' % (dirname, s.filename), 'w') as f:
         f.write(s.file)
         f.close()

      # Archive all sub objects
      for data in s.sub_objects:
         fname = hashlib.md5(data).hexdigest()
         with open('%s/%s' % (dirname, fname), 'w') as f:
            f.write(data)
            f.close
   except:
      e = sys.exc_info()[0]
      s.dbg_h.error('%s There was an error writing to the export directory. Error: %s' % (dt.now(), e))

   return dirname

# Result: Process object and sub objects, review results, pass dictionary back
def scan_file(s):

   # Determine if we need to save sub object buffers
   if s.full == 'True' or \
   s.archive == 'all-the-things' or \
   s.archive == 'all-on-alert':
      global SUB_TRACKER 
      SUB_TRACKER = True

   # Scan and process the results
   root_dict = OrderedDict([('Scan Time', '%s' % dt.now()),
                            ('Filename', s.filename),
                            ('Source', s.source),
                            ('Object', process_buffer(s, s.file))])

   root_dict['Summary'] = { 'Modules' : sorted(set(MODULES_RUN)),
                            'Yara' : sorted(set(YARA_RULES)) }

   # Allow post processor to add observations on output
   root_dict['Summary']['Observations'] = post_processor(s, root_dict)

   if s.alert:
      root_dict['Alert'] = True
      # Archive file on alert
      if s.archive == 'file-on-alert':
         root_dict['Export'] = archive_file(s)
      # Archive file and sub objects on alert
      if s.archive == 'all-on-alert':
         root_dict['Export'] = archive_all(s, root_dict)
   else:
      root_dict['Alert'] = False

   # Archive all the files, regardless of alert status
   if s.archive == 'all-the-files':
      root_dict['Export'] = archive_file(s)   

   # Archive all the things, regardless of alert status
   if s.archive == 'all-the-things':
      root_dict['Export'] = archive_all(s, root_dict)

   return root_dict
