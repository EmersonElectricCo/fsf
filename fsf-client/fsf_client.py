#!/usr/bin/python
#
# FSF Client for sending information and generating a report
#
# Jason Batchelor
# Emerson Corporation
# 10/30/2015
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

class FSFClient:
   def __init__(self, fullpath, filename, not_interactive, full, file):

         self.fullpath = fullpath
         self.filename = filename
         self.not_interactive = not_interactive
         self.full = full
         self.file = file
         # If multiple server candidates are given, we randomly choose one
         self.host = random.choice(config.SERVER_CONFIG['IP_ADDRESS'])
         self.port = config.SERVER_CONFIG['PORT']
         self.logfile = config.CLIENT_CONFIG['LOG_FILE']

   # Send files to server for processing and await results
   def process_files(self):

      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      msg = '%sFSF_RPC%sFSF_RPC%sFSF_RPC%s' % (self.filename, self.not_interactive, self.full, self.file)
      buffer = struct.pack('>I', len(msg)) + msg

      try:
         sock.connect((self.host, self.port))
         sock.sendall(buffer)

      except:
         e = sys.exc_info()[0]
         error = '%s There was a problem sending file %s to %s on port %s. Error: %s\n' % (dt.now(), self.filename, self.host, self.port, e)

         if self.not_interactive:
            with open(self.logfile, 'a') as f:
               f.write(error)
               f.close()
         else:
            print error

      finally:

         if self.not_interactive:
            os.remove(self.fullpath)
         else:
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
        if self.not_interactive:
           with open(self.logfile, 'a') as f:
              f.write(error)
              f.close()
        else:
           print error

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

      print 'Subobjects of %s successfully written to: %s' % (self.filename, dirname)

if __name__ == '__main__':

   parser = argparse.ArgumentParser(prog='fsf_client', description='Uploads files to scanner server and, depending on the mode being used, either returns the results to the user or writes a report to a server side log file.')
   parser.add_argument('file', nargs='*', type=argparse.FileType('r'), help='Full path to file(s) to be procsesed.')
   parser.add_argument('--not-interactive', default=False, action='store_true', help='Not running in interactive mode will cause results to be logged passively to the server only. The data sent will also be REMOVED from the client after it is sent. Only files that meet archival criteria will be saved on the server in the configured export directory. This mode is generally used for automated file extraction operations, not analyst interaction.')
   parser.add_argument('--full', default=False, action='store_true', help='Dump all subobjects of submitted file to current directory. Format or directory name is \'fsf_dump_[epoch time]_[md5 hash of scan results]\'. Currently only supported in interactive mode (default).')

   if len(sys.argv) == 1:
      parser.print_help()
      sys.exit(1)

   try:
      args = parser.parse_args()
   except IOError:
      e = sys.exc_info()[1]
      print 'The file provided could not be found. Error: %s' % e
      sys.exit(1)

   for f in args.file:
      filename = os.path.basename(f.name)
      file = f.read()
      fsf = FSFClient(f.name, filename, args.not_interactive, args.full, file)
      fsf.process_files()
