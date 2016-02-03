#!/usr/bin/python
#
# Author: Jason Batchelor
# Description: Search VirusTotal database based on computed hash of buffer
# Can be used as a default module (if desired) or more tactically applied
# (ie only EXE files with high entropy, etc). It depends on you and your API
# usage limits. When you are set up, just add this to the dispositioner file.
# Date: 01/06/2016
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
import hashlib
import requests

def META_VT_INSPECT(s, buff):

   md5 = hashlib.md5(buff).hexdigest()
   params = {'apikey' : 'YOUR API KEY HERE',
             'resource' : md5 }
   base_uri = 'https://www.virustotal.com/vtapi/v2'
   response = requests.get('%s/%s' % (base_uri, 'file/report'), params=params)
   response_json = response.json()

   return response_json

if __name__ == '__main__':
   print META_VT_INSPECT(None, sys.stdin.read())
