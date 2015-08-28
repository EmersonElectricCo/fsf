#!/usr/bin/python
#
# FSF Client for sending information and generating a report
#
# Author: Jason Batchelor
# Company: Emerson
# Date: 5/8/2015
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
from conf import config
from datetime import datetime as dt

class FSFClient:
   def __init__(self, fullpath, filename, not_interactive, file):

      self.fullpath = fullpath
      self.filename = filename
      self.not_interactive = not_interactive
      self.file = file
      self.host = config.SERVER_CONFIG['IP_ADDRESS']
      self.port = config.SERVER_CONFIG['PORT']
      self.logfile = config.CLIENT_CONFIG['LOG_FILE']

   def process_files(self):

      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      msg = '%sFSF_RPC%sFSF_RPC%s' % (self.filename, self.not_interactive, self.file)
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

   def process_results(self, sock):

      try:
         raw_msg_len = sock.recv(4)
         msg_len = struct.unpack('>I', raw_msg_len)[0]
         data = ''

         while len(data) < msg_len:
            recv_buff = sock.recv(msg_len - len(data))
            data += recv_buff

         print data

      except:
         e = sys.exc_info()[0]
         error = '%s There was a problem getting data for %s from %s on port %s. Error: %s' % (dt.now(), self.filename, self.host, self.port, e)

         if self.not_interactive:
            with open(self.logfile, 'a') as f:
               f.write(error)
               f.close()
         else:
            print error

if __name__ == '__main__':

   parser = argparse.ArgumentParser(prog='fsf_client', description='Uploads files to scanner server and, depending on the mode being used, either returns the results to the user or writes them to a server side log file.')
   parser.add_argument('file', nargs='*', type=argparse.FileType('r'), help='Full path to file(s) to be procsesed.')
   parser.add_argument('--not-interactive', default=False, action='store_true', help='Not running in interactive mode will cause results to be logged passively to the server only. The data sent will also be REMOVED from the client after it is sent. Only files that meet archival criteria will be saved on the server in the configured export directory. This mode is generally used for automated file extraction operations, not analyst interaction.')

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
      fsf = FSFClient(f.name, filename, args.not_interactive, file)
      fsf.process_files()
