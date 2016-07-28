#!/usr/bin/env python
#
# FSF Client for sending information and generating a report
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

import os
import sys
import socket
import argparse
import struct
import json
import time
import hashlib
import random
from conf import config
from datetime import datetime as dt
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, FileSystemEventHandler

class FSFClient:
   def __init__(self, fullpath, filename, delete, source, archive, suppress_report, full, file):

         self.fullpath = fullpath
         self.filename = filename
         self.delete = delete
         self.source = source
         self.archive = archive
         self.suppress_report = suppress_report
         self.full = full
         self.file = file
         # If multiple server candidates are given, we randomly choose one
         self.host = random.choice(config.SERVER_CONFIG['IP_ADDRESS'])
         self.port = config.SERVER_CONFIG['PORT']
         self.logfile = config.CLIENT_CONFIG['LOG_FILE']

         archive_options = ['none', 'file-on-alert', 'all-on-alert', 'all-the-files', 'all-the-things']
         if args.archive not in archive_options:
            error = '%s Please specify a valid archive option: \'none\', \'file-on-alert\', \'all-on-alert\', \'all-the-files\' or \'all-the-things\'.\n' % dt.now()
            self.issue_error(error)
            sys.exit(1)

   # Send files to server for processing and await results
   def process_files(self):

      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      msg = '%sFSF_RPC%sFSF_RPC%sFSF_RPC%sFSF_RPC%sFSF_RPC%s' % (self.filename, self.source, self.archive, self.suppress_report, self.full, self.file)
      buffer = struct.pack('>I', len(msg)) + 'FSF_RPC' + msg

      try:
         sock.connect((self.host, self.port))
         sock.sendall(buffer)
      except:
         e = sys.exc_info()[0]
         error = '%s There was a problem sending file %s to %s on port %s. Error: %s\n' % (dt.now(), self.filename, self.host, self.port, e)
         self.issue_error(error)

      finally:

         if self.delete:
            os.remove(self.fullpath)

         if not self.suppress_report:
            self.process_results(sock)

         sock.close()

   # Process the results sent back from the FSF server
   def process_results(self, sock):

      try:
         raw_msg_len = sock.recv(4)
         msg_len = struct.unpack('>I', raw_msg_len)[0]
         data = ''

         while len(data) < msg_len:
            recv_buff = sock.recv(msg_len - len(data))
            data += recv_buff

         print data

         # Does the user want all sub objects?
         if self.full:
            # Generate dirname by calculating epoch time and hash of results
            dirname = 'fsf_dump_%s_%s' % (int(time.time()), hashlib.md5(data).hexdigest())
            self.dump_subobjects(sock, dirname)

      except:
         e = sys.exc_info()[0]
         error = '%s There was a problem getting data for %s from %s on port %s. Error: %s' % (dt.now(), self.filename, self.host, self.port, e)
         self.issue_error(error)

   # Dump all subobjects returned by the scanner server
   def dump_subobjects(self, sock, dirname):

      sub_status = sock.recv(4)
      if sub_status == 'Null':
         print 'No subobjects were returned from scanner for %s.' % self.filename
         return

      os.mkdir(dirname)

      while self.full:
         raw_sub_count = sock.recv(4)
         sub_count = struct.unpack('>I', raw_sub_count)[0]
         raw_msg_len = sock.recv(4)
         msg_len = struct.unpack('>I', raw_msg_len)[0]
         data = ''

         while len(data) < msg_len:
            recv_buff = sock.recv(msg_len - len(data))
            data += recv_buff

         fname = hashlib.md5(data).hexdigest()
         with open('%s/%s' % (dirname, fname), 'w') as f:
            f.write(data)
            f.close

         if sub_count == 0:
            self.full = False

      print 'Sub objects of %s successfully written to: %s' % (self.filename, dirname)

   # Either log to log file or print to stdout depending on flags used
   def issue_error(self, error):

      if self.suppress_report:
         with open(self.logfile, 'a') as f:
            f.write(error)
            f.close()
      else:
         print error

class event_scanfsf(FileSystemEventHandler):
    """Logs all the events captured."""

    def on_created(self, event):
        if not event.is_directory:
            try:
                with open(event.src_path) as f:
                    file = f.read()
                    fsf = FSFClient(event.src_path, event.src_path, "", "", "none", "", "", file)
                    fsf.process_files()
            except:
                sys.stderr.write('Could not open file {0}\n'.format(event.src_path))

def filedir_open(string):
   if not os.path.exists(string):
      sys.exit(1)
   if os.path.isdir(string):
      return string
   else:
      try:
         f = open(string, 'r')
      except IOError, why:
         sys.stderr.write('Could not open file or directory. Error {0}\n'.format(why))
         sys.exit(1)

   return f

def watch_single_dir(path):
   if hasattr(path, 'name'):
      sys.stderr.write('Not a directory - {0}\n'.format(path.name))
      sys.exit(1)
   if not os.path.exists(path):
      sys.stderr.write('Directory {0} does not exist\n'.format(path))
      sys.exit(1)
   if not os.path.isdir(path):
      sys.stderr.write('Not a directory - {0}\n'.format(path))
      sys.exit(1)

   event_handler = event_scanfsf()
   observer = Observer()
   observer.schedule(event_handler, path, recursive=False)
   observer.start()

   try:
       while True:
           time.sleep(1)
   except KeyboardInterrupt:
       observer.stop()

   observer.join()

if __name__ == '__main__':
   parser = argparse.ArgumentParser(prog='fsf_client', description='Uploads files to scanner server and returns the results to the user if desired. Results will always be written to a server side log file. Default options for each flag are designed to accommodate easy analyst interaction. Adjustments can be made to accommodate larger operations. Read the documentation for more details!')
   parser.add_argument('file', nargs='*', type=filedir_open, help='Full path to file(s) to be processed.')
   parser.add_argument('--delete', default=False, action='store_true', help='Remove file from client after sending to the FSF server. Data can be archived later on server depending on selected options.')
   parser.add_argument('--source', nargs='?', type=str, default='Analyst', help='Specify the source of the input. Useful when scaling up to larger operations or supporting multiple input sources, such as; integrating with a sensor grid or other network defense solutions. Defaults to \'Analyst\' as submission source.')
   parser.add_argument('--archive', nargs='?', type=str, default='none', help='Specify the archive option to use. The most common option is \'none\' which will tell the server not to archive for this submission (default). \'file-on-alert\' will archive the file only if the alert flag is set. \'all-on-alert\' will archive the file and all sub objects if the alert flag is set. \'all-the-files\' will archive all the files sent to the scanner regardless of the alert flag. \'all-the-things\' will archive the file and all sub objects regardless of the alert flag.')
   parser.add_argument('--suppress-report', default=False, action='store_true', help='Don\'t return a JSON report back to the client and log client-side errors to the locally configured log directory. Choosing this will log scan results server-side only. Needed for automated scanning use cases when sending large amount of files for bulk collection. Set to false by default.')
   parser.add_argument('--full', default=False, action='store_true', help='Dump all sub objects of submitted file to current directory of the client. Format or directory name is \'fsf_dump_[epoch time]_[md5 hash of scan results]\'. Only supported when suppress-report option is false (default).')
   parser.add_argument('--watchdir', default=False, action='store_true', help='Monitor a given directory and scan all uploaded files.')

   if len(sys.argv) == 1:
      parser.print_help()
      sys.exit(1)

   try:
      args = parser.parse_args()
   except IOError:
      e = sys.exc_info()[1]
      print 'The file provided could not be found. Error: %s' % e
      sys.exit(1)

   if args.watchdir:
      print 'Running in a daemon mode'
      watch_single_dir(args.file[0])
      sys.exit(0)

   if len(args.file) == 0:
      print 'A file to scan needs to be provided!' 

   for f in args.file:
      if hasattr(f, 'name'):
         filename = os.path.basename(f.name)
         file = f.read()
         fsf = FSFClient(f.name, filename, args.delete, args.source, args.archive, args.suppress_report, args.full, file)
         fsf.process_files()
      else:
         sys.stderr.write('Error while processing {0} - not a file?\n'.format(f))
         sys.exit(1)
