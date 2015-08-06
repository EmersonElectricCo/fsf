#!/usr/bin/python
#
# Listen, accept, and queue incomming files.
#
# Jason Batchelor
# Emerson Corporation
# 04/22/2015
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
import struct
import threading
import SocketServer
import json
from daemon import Daemon
from conf import config
from datetime import datetime as dt

class ScannerDaemon(Daemon):

   def run(self):
      HOST = config.SERVER_CONFIG['IP_ADDRESS']
      PORT = config.SERVER_CONFIG['PORT']

      try:
         self.fsf_server = ForkingTCPServer((HOST, PORT), ForkingTCPRequestHandler)
      except:
         print 'Could not initialize server... am I already running?'
         sys.exit(2)

      fsf_server_thread = threading.Thread(target=self.fsf_server.serve_forever)
      #fsf_server_thread.daemon = True
      fsf_server_thread.start()

class ForkingTCPRequestHandler(SocketServer.BaseRequestHandler):

   def handle(self):

      from scanner import Scanner

      s = Scanner()
      s.check_directories()
      s.initialize_logger()
      s.check_yara_file()

      try:
         raw_msg_len = self.request.recv(4)
         msg_len = struct.unpack('>I', raw_msg_len)[0]
         data = ''

         while len(data) < msg_len:
            
            recv_buff = self.request.recv(msg_len - len(data))
            data += recv_buff

         self.process_data(data, s)
   
      except:
         e = sys.exc_info()[0]
         s.dbg_h.error('%s There was a problem processing the connection request from %s. Error: %s' % (dt.now(), self.request.getpeername()[0], e))
      finally:
         self.request.close()

   def process_data(self, data, s):

      try:
         s.filename, s.not_interactive, s.file = data.split('FSF_RPC')
         results = s.scan_file()

         if s.not_interactive == 'True':
            s.scan_h.info(json.dumps(results, sort_keys=False))
         else:
            s.scan_h.info(json.dumps(results, sort_keys=False))
            msg = json.dumps(results, indent=4, sort_keys=False)
            buffer = struct.pack('>I', len(msg)) + msg
            self.request.sendall(buffer)
      except:
         e = sys.exc_info()[0]
         s.dbg_h.error('%s There was an error generating scanner results. Error: %s' % (dt.now(), e))

class ForkingTCPServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
   pass

if __name__ == "__main__":

   daemon_logger = '%s/%s' % (config.SCANNER_CONFIG['LOG_PATH'], 'daemon.log')

   if len(sys.argv) != 2:
      print "usage: %s start|stop|restart" % sys.argv[0]
      sys.exit(2)

   with open(daemon_logger, 'a') as fh:
      fh.write('%s Daemon given %s command\n' % (dt.now(), sys.argv[1]))

   daemon = ScannerDaemon('/tmp/scanner.pid', stdin=daemon_logger, stdout=daemon_logger, stderr=daemon_logger)

   if 'start' == sys.argv[1]:
      daemon.start()
   elif 'stop' == sys.argv[1]:
      daemon.stop()
   elif 'restart' == sys.argv[1]:
      daemon.restart()
   else:
      print "Unknown command"
      sys.exit(2)
   sys.exit(0)
