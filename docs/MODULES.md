Writing Modules
==============

Purpose
------------

This documentation will go over the process of making contributions to the File Scanning Framework. Modules are intended to be very easy to write and contribute. They can even be dynamically updated on a scanning service while the daemon is running.

Fundamentals
------------

The following is a bulleted list of important files within the framework and their purpose. 

* `conf/config.py` - Configuration file for the server. Used to define IP address and port to listen on, timeout value for each module, where the central Yara file is with all the includes, where to export files that trigger an alert, and how deep to recursively process a single object.
* `conf/disposition.py` - Configuration file used to define any actions that should be taken on files being processed. Drives alerting decisions on files that match Yara signatures and defines module(s) to run as a result of a signature hit.
* `modules/` - Add your modules here to incorporate them into the framework by editing the `__init__.py` file. Ensure your module is in the _modules_ directory.

The scanner can be invoked in two modes 

* _Not-interactive mode_ - Not running in interactive mode will cause results to be logged passively to the server only. The data sent will also be __REMOVED__ from the client after it is sent. Only files that meet archival criteria will be saved on the server in the configured export directory. This mode is generally used for automated file extraction operations, not analyst interaction.
* _Interactive mode_ - This is the default mode, primarily used for analyst interaction. Results are displayed to the analyst and are also logged on the server in the configured location. Files sent are not deleted off the system and are not able to be alerted on. This makes the most sense, as analysts will be scanning known malware specimens that do not require an alert.

Module Overview
------------
All modules are stored in the _modules_ directory and follow a loosely defined naming convention where the META prefix is sole purposed for returning metadata from a parsed buffer and EXTRACT is used to denote modules that do some level of decoding or decompression, perhaps in addition to returning metadata. 

There is a `modules/template.py` file in the modules directory that is a simple starting point. 

###Module Requirements###

* By convention, your module must have a function with your modules name. (Example: A module named META_TEST.py should have a function named META_TEST).
 * This is what FSF will call when your module is plugged in
 * This function must accept two parameters, a scanner object and a buffer to process
 * The main function must return a dictionary
  * Empty dictionary objects are deleted before displaced

###Scanner Object###

Modules are granted access to a scanner object which has the following attributes:
* Filename - (String) - name of the initial file being analyzed
* Not interactive - (Boolean) Value that states how server was invoked
* File - (List) - buffer of initial file being analyzed
* Yara Rule Path - (String) - Path to central yara file with all includes
* Export Path - (String) - Where files should be written to
* Log Path - (String) - Where logs should be written to
* Max Depth - (Int) - How deep we should recurse through each object tree
* Debug Log - (Logger Object) - Writing to debug logger file
* Scan Log - (Logger Object) - Writing to scan logger file
* Timeout - (Int) - How long each module has before it is forced to exit
* Alert - (Boolean) - Value sets the alert key 

###File Recursion###

Returned buffers are processed recursively with the framework, and the convention for doing this is to simply append the buffer you plan on returning affixed to a dictionary key named _Buffer_. Doing so will cause the processor script to iterate through the assigned values and run modules on them as defined in the _conf/dispositioner.py_ file.

If you need to return multiple buffers for whatever reason, you might want to consider a parent/child hierarchy, where your parent dictionary is assigned an object identifier for a key and a child dictionary with your _Buffer_ key and value pair. The modules EXTRACT_RAR and EXTRACT_ZIP are good examples of this.  

###Adding a Module###

The following steps need to be followed when adding a module to the framework.

* Ensure the `modules/__init__.py` file is updated to contain the new modules name. 
* Add logic in the `conf/dispositioner.py` file to ensure your module is run
 * Can choose to have your module run all the time (default modules list)
 * Can choose to have module run only when a Yara signature hits
  * If necessary, create the Yara signature that triggers it

Your First Module
------------

Let's write a module that processes a new file type we're interested in. This file is defined by the 'JXB' header and we want to parse our fictional file which is defined by the following pseudo-structure.

```
 struct my_test
 {
    char header[3];
    BYTE xorkey;
    char secret[10];
 } 
```

Our module should be invoked when our file type is encoded, and then uses the xorkey we derive to decode the secret message. 

Lets use the following command to generate our test file.

`echo -ne 'JXB\x51\x3e\x24\x23\x71\x37\x38\x23\x22\x25\x71\x3c\x3e\x35\x24\x3d\x34' > test_file`

A Yara rule that would flag on a file like this might be as follows...

```
 rule my_test
 {
    meta:
       author = "[your name]"
       lastmod = "20150729"
       desc = "[description of signature]"
 
    strings:
       $magic = "JXB"
 
    condition:
       $magic at 0
 }
```

We need to ensure the include for this signature is added to where ever our chief Yara file the server side scanner is configured to point to. 

Example code to test out our module would be as follows...

```
 import sys
 
 def META_TEST_DECODE(s, buff):
    TEST = {}
 
    xor_key = ord(buff[3])
    decode = []
 
    for i in buff[4:]:
       decode.append(chr(ord(i) ^ xor_key))
 
    TEST['Message'] = ''.join(decode)
    TEST['XOR Key'] = hex(xor_key)
 
    return TEST
 
 if __name__ == '__main__':
    print META_TEST_DECODE(None, sys.stdin.read())
```

Testing this outside the framework produces our expected result.

```
 cat test_file | python META_TEST_DECODE.py
 {'Message': 'our first module', 'XOR Key': '0x51'}
```

Now to integrate within our framework.

Edit the `modules/__init__.py` file to add the module and then edit the `disposition.py` file in `conf/` to add our signature, and the module we want run, we also want to set the alert key to True. 

` ('my_test', ['META_TEST_DECODE'], True),`

Finally, start the scanner server daemon in fsf-server. Ensure the server configuration file is setup properly before proceeding.

` ./main.py start`

Next, move over to the fsf-client and ensure the `conf/config.py` file is pointing to your server and other parameters are set. Once things are set up right, invoke the client and you should get back a JSON report inclusive of your module, congrats!

```
 ./fsf_client.py test_file
 {
     "Scan Time": "2015-07-29 12:38:18.095262",
     "Filename": "test_file",
     "Object": {
         "META_BASIC_INFO": {
             "SHA1": "fc9ed5d80e1d5170b2a6c17673ddbf5bd7dd579e",
             "MD5": "379ff2d43a6aa065c0bae65108815d20",
             "ssdeep": "3:WbE40B8:WbE47",
             "SHA256": "6755b15031b263127dfa38b0275bf1e901b6711b636905245338a2e9835f9ed2",
             "SHA512": "d51021afd7de53fd3546d1cd9a5aba1bacdafa1a94377ab2d10b90943a6bf708a821a20decd08311c19d5dc3a3b701a972bd5db1e1881b16b6ea1d046fdce5bb",
             "Size": "20 bytes"
         },
         "SCAN_YARA": {
             "my_test": {
                 "desc": "[description of signature]",
                 "lastmod": "20150729",
                 "author": "[your name]"
             }
         },
         "META_TEST_DECODE": {
             "Message": "our first module",
             "XOR Key": "0x51"
         }
     },
     "Interactive": true,
     "Alert": true
 }
```

Debugging
------------

All modules are passed both a scanner object and a buffer in the form of a list directly. It is suggested practice to begin debugging by feeding your module an example file directly and reading that from STDIN and printing the dictionary output. 

Once you've achieved success getting the desired output in the form of a returned dictionary, you can plug the module in to the framework by following the above instructions, and attempt to run the `fsf-client.py` script against the configured server. Your returned output should be a JSON object including your modules returned data.

Areas to troubleshoot for difficulties running at this level on the server side are the `dbg.log` file and the `daemon.log` file. On the client side, if the not-interactive flag is set, difficulties are logged to the client. All are written to the configured log path. 

Automated File Extraction
------------

###Bro###

The following Bro script was compiled and tested with Bro 2.4. After simply adding it to the ''local.bro'' file and deploying, you should be all set! This script aids in the automatic extraction of files, and the sending of those files to an FSF server.

```
 # Jason Batchelor
 # Extract files over various protocols
 # 6/19/2015
 
 export
 {
         # Define the file types we are interested in extracting
         const ext_map: table[string] of string = {
                 ["application/x-dosexec"] = "exe",
                 ... ADD MIME TYPES TO EXTRACT HERE ...
         } &redef &default="";
 }
  
 # Set extraction folder
 redef FileExtract::prefix = "WHERE FILES ARE WRITTEN";
 
 event file_sniff(f: fa_file, meta: fa_metadata)
 {
         local ext = "";
 
         if ( meta?$mime_type )
         {
                 ext = ext_map[meta$mime_type];
         }
 
         if ( ext == "" )
         {
                 return;
         }
         # Hash the file for good measure
         Files::add_analyzer(f, Files::ANALYZER_MD5);
 
         local fname = fmt("%s-%s-%s", f$source, f$id, ext);
         Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname, $extract_limit=FILE LIMIT]);
 }
 
 event file_state_remove(f: fa_file)
 {
         if ( f$info?$extracted )
         {
                 # Invoke the scanner in not interactive mode. Files will be deleted off client once sent, this is a fail open operation
                 local scan_cmd = fmt("%s %s/%s", "PATH/fsf_client.py --not-interactive", FileExtract::prefix, f$info$extracted);
                 system(scan_cmd);
         }
 }
```

To ensure things are going smoothly, check the client_dbg.log file to see if there are any errors being generated. Next tail the scanner log file and hopefully you will begin seeing JSON reports of all the files being written. You can aggregate these reports to your favorite indexer or SIMS!

