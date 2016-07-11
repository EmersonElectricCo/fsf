#!/usr/bin/env python
#
# Base class for scanner framework.
#
# Jason Batchelor
# Emerson Corporation
# 02/10/2016
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

import os
import sys
import argparse
import logging
import processor
from cloghandler import ConcurrentRotatingFileHandler
from conf import config
from datetime import datetime as dt

class Scanner:
   def __init__(self):

      self.filename = ""
      self.source = ""
      self.archive = ""
      self.suppress_report = ""
      self.file = ""
      self.yara_rule_path = config.SCANNER_CONFIG['YARA_PATH']
      self.export_path = config.SCANNER_CONFIG['EXPORT_PATH']
      self.log_path = config.SCANNER_CONFIG['LOG_PATH']
      self.max_depth = config.SCANNER_CONFIG['MAX_DEPTH']
      self.dbg_h = ""
      self.scan_h = ""
      self.timeout = config.SCANNER_CONFIG['TIMEOUT']
      self.alert = False
      self.full = ""
      self.sub_objects = []

   def check_directories(self):

      # Create log dir if it does not exist
      if not os.path.isdir(self.log_path):
         try:
            os.makedirs(self.log_path)
         except:
            print 'Unable to create logging directory: %s. Check permissions?' \
            % self.log_path
            sys.exit(2)

      # Create export dir if it does not exist
      if not os.path.isdir(self.export_path):
         try:
            os.makedirs(self.export_path)
         except:
            e = sys.exc_info()[0]
            print 'Unable to create export directory: %s. Check permissions?' \
            % self.export_path
            sys.exit(2)

   def initialize_logger(self):

      # Invoke logging with a concurrent logging module since many of these
      # processes will likely be writing to scan.log at the same time
      self.dbg_h = logging.getLogger('dbg_log')
      dbglog = '%s/%s' % (self.log_path, 'dbg.log')
      dbg_rotateHandler = ConcurrentRotatingFileHandler(dbglog, "a")
      self.dbg_h.addHandler(dbg_rotateHandler)
      self.dbg_h.setLevel(logging.ERROR)

      self.scan_h = logging.getLogger('scan_log')
      scanlog = '%s/%s' % (self.log_path, 'scan.log')
      scan_rotateHandler = ConcurrentRotatingFileHandler(scanlog, "a")
      self.scan_h.addHandler(scan_rotateHandler)
      self.scan_h.setLevel(logging.INFO)

   def check_yara_file(self):

      # Ensure Yara rule file exists before proceeding
      if not os.path.isfile(self.yara_rule_path):
         self.dbg_h.error('%s Could not load Yara rule file. File %s, does not exist!' % (dt.now(), self.yara_rule_path))
         sys.exit(2)

   def scan_file(self):
      return processor.scan_file(self)
