#!/usr/bin/python
#
# Author: Jason Batchelor
# Description: Get metadata on the signature used to sign a PE file
# Date: 11/17/2015
# 
# Good resources:
# * https://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt
# * http://erny-rev.blogspot.com/2013/10/parsing-x509v3-certificates-and-pkcs7.html
# * http://pyasn1.sourceforge.net/
# * https://msdn.microsoft.com/en-us/windows/hardware/gg463180.aspx
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
import pefile
import struct
from datetime import datetime
from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc2315

# Reference: https://msdn.microsoft.com/en-us/library/ff635603.aspx
def hash_alg_oid_mapping():

   db = {}
   db['1.2.840.113549.1.1.5'] = 'sha1RSA'
   db['1.2.840.113549.1.1.4'] = 'md5RSA'
   db['1.2.840.10040.4.3'] = 'sha1DSA'
   db['1.3.14.3.2.29'] = 'sha1RSA'
   db['1.3.14.3.2.15'] = 'shaRSA'
   db['1.3.14.3.2.3'] = 'md5RSA'
   db['1.2.840.113549.1.1.2'] = 'md2RSA'
   db['1.2.840.113549.1.1.3'] = 'md4RSA'
   db['1.3.14.3.2.2'] = 'md4RSA'
   db['1.3.14.3.2.4'] = 'md4RSA'
   db['1.3.14.7.2.3.1'] = 'md2RSA'
   db['1.3.14.3.2.13'] = 'sha1DSA'
   db['1.3.14.3.2.27'] = 'dsaSHA1'
   db['2.16.840.1.101.2.1.1.19'] = 'mosaicUpdatedSig'
   db['1.3.14.3.2.26'] = 'sha1NoSign'
   db['1.2.840.113549.2.5'] = 'md5NoSign'
   db['2.16.840.1.101.3.4.2.1'] = 'sha256NoSign'
   db['2.16.840.1.101.3.4.2.2'] = 'sha384NoSign'
   db['2.16.840.1.101.3.4.2.3'] = 'sha512NoSign'
   db['1.2.840.113549.1.1.11'] = 'sha256RSA'
   db['1.2.840.113549.1.1.12'] = 'sha384RSA'
   db['1.2.840.113549.1.1.13'] = 'sha512RSA'
   db['1.2.840.113549.1.1.10'] = 'RSASSA-PSS'
   db['1.2.840.10045.4.1'] = 'sha1ECDSA'
   db['1.2.840.10045.4.3.2'] = 'sha256ECDSA'
   db['1.2.840.10045.4.3.3'] = 'sha384ECDSA'
   db['1.2.840.10045.4.3.4'] = 'sha512ECDSA'
   db['1.2.840.10045.4.3'] = 'specifiedECDSA'

   return db

# Reference: https://msdn.microsoft.com/en-us/library/windows/desktop/aa386991(v=vs.85).aspx
def rdn_oid_mapping():

   db = {}
   db['2.5.4.3']  = 'CN'
   db['2.5.4.5']  = 'DeviceSerialNumber'
   db['2.5.4.6']  = 'C'
   db['2.5.4.7']  = 'L'
   db['2.5.4.8']  = 'ST'
   db['2.5.4.10'] = 'O'
   db['2.5.4.11'] = 'OU'
   db['1.2.840.113549.1.9.1'] = 'E'

   return db

def get_cert_info(signed_data):

   PARENT_CERT_INFO = {} 
   rdn_mapping = rdn_oid_mapping()
   hash_mapping = hash_alg_oid_mapping()
   cert_count = 0

   for c in signed_data['certificates']:

      CERT_INFO = {}
      cer = c['certificate']['tbsCertificate']

      CERT_INFO['Version'] = cer['version'].prettyPrint()[1:-1] # the [1:-1] is a fun way to get rid of double quotes

      CERT_INFO['Algorithm'] = hash_mapping[cer['signature']['algorithm'].prettyPrint()]

      # Had do get creative here with the formatting.. 
      serial = '%.02x' % int(cer['serialNumber'].prettyPrint())
      # Append a zero to the front if we have an odd number of hex digits
      serial = '0' + serial if len(serial) % 2 != 0 else serial
      # Finally, apply our colon in between the hex bytes
      serial = ':'.join(serial[i:i+2] for i in range(0, len(serial), 2))
      CERT_INFO['Serial'] = serial

      CERT_INFO['Validity'] = { 'Not Before' : datetime.strptime(str(cer['validity']['notBefore']['utcTime']), '%y%m%d%H%M%SZ').strftime("%Y-%m-%d %H:%M:%S UTC"),
                                'Not After' : datetime.strptime(str(cer['validity']['notAfter']['utcTime']), '%y%m%d%H%M%SZ').strftime("%Y-%m-%d %H:%M:%S UTC") }

      subject = cer['subject']
      issuer = cer['issuer']

      rdnsequence = subject[0]
      CERT_INFO['Subject'] = []
      for rdn in rdnsequence:
         oid, value = rdn[0]
         if oid.prettyPrint() in rdn_mapping:         
            CERT_INFO['Subject'].append('%s=%s' % (rdn_mapping[oid.prettyPrint()], str(value[2:])))

      rdnsequence = issuer[0]
      CERT_INFO['Issuer'] = []
      for rdn in rdnsequence:
         oid, value = rdn[0]
         if oid.prettyPrint() in rdn_mapping:
            CERT_INFO['Issuer'].append('%s=%s' % (rdn_mapping[oid.prettyPrint()], str(value[2:])))

      PARENT_CERT_INFO['Cert_%s' % cert_count] = CERT_INFO
      cert_count += 1

   return PARENT_CERT_INFO
      
def META_PE_SIGNATURE(s, buff):

   sig_buff = []

   pe = pefile.PE(data=buff)

   address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
   size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

   # Eight bytes in due to the struct spec
   # typedef struct _WIN_CERTIFICATE
   # {
   #     DWORD       dwLength;
   #     WORD        wRevision;
   #     WORD        wCertificateType;   
   #     BYTE        bCertificate[ANYSIZE_ARRAY];
   # } WIN_CERTIFICATE, *LPWIN_CERTIFICATE;
   sig_buff = buff[address + 8 : address + 8 + size]
   # Remove sequence and objid structures, 19 bytes
   signed_data, rest = decode(sig_buff[19:], asn1Spec=rfc2315.SignedData())

   return get_cert_info(signed_data)

if __name__ == '__main__':
   print META_PE_SIGNATURE(None, sys.stdin.read())
