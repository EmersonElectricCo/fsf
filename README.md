File Scanning Framework (FSF) v1.1
==============

Introduction
------------

###What is the ‘file scanning framework’?###

Network defenders should be empowered to drive capabilities forward how they see fit. This is the philosophy upon which, FSF was designed.

FSF is a modular, recursive file scanning solution. FSF enables analysts to extend the utility of the Yara signatures they write and define actionable intelligence within a file. This is accomplished by recursively scanning a file and looking for opportunities to extract file objects using a combination of Yara signatures (to define opportunities) and programmable logic (to define what to do with the opportunity).
The framework allows you to build out your intelligence capability by empowering you to apply observations wrought out of the analytical process…

Okay that’s a mouthful – but think about it – if you see that some pattern (maybe a string or a byte sequence) that represents some concept or behavior; through the use of the framework, you are positioned to capture that observation and apply it to certain file types that meet your criteria. The goal being, to help extend the utility for observations from malware analysis and reverse engineering efforts.

Some examples might be:
* Uncompressing ZIP files and scanning their contents.
* Decoding a malware config file that matches a specific signature, then parsing the meta data.
* General metadata enrichment for any file type.
 * Logging the compile time for any EXE
 * Logging the author field for office documents
 * So much more...

You can extend and define what’s important by writing modules that expose pieces of metadata that inform analysis and expose new sub objects of a file! These sub objects are recursively scanned through the same gauntlet, further enhancing both Yara and module utility.

Once that is complete, you can add jq filters using the post-processing feature to capture certain items of interest from FSF output. Both Yara and jq may be used to capture observations and drive innovative detections!

###If we alert on a signature, how will we know?###

This decision is left up to you since there are many ways to do this. One suggestion might be to aggregate and index the scan.log data using something like [Splunk](http://www.splunk.com/) or with an [ELK Stack](http://brewhouse.io/blog/2014/11/04/big-data-with-elk-stack.html). You can then build your alerting into the capability.

###Is there a way I can take action on a specific rule hit from within the FSF? Like print out metadata for certain file types?###

This is precisely what modules are for! Module development driven by analyst observations is a cornerstone of the FSF!

###What if I want to capture high level observations and even detect on relationships between files that FSF exposes?###

This is all done via a post-processing feature that is driven in large part by jq (a JSON interpreter). To learn more about how to write jq filters that work with the FSF post-processor, check out [docs/jq_filters.md](https://github.com/EmersonElectricCo/fsf/blob/master/docs/JQ_FILTERS.md).

###This is pretty cool – but I don’t really know that much about Yara or jq?###

Check out the [Yara official documentation](http://yara.readthedocs.org/) for more information and examples for Yara.

The official [jq](https://stedolan.github.io/jq/) website contains great tutorials and documentation as well.

###What are the tools limitations?###

* Since we recursively process objects, a `MIN_DEPTH` configurable value is enforced.
* There is a `TIMEOUT` value that is imposed on each module run that may not be exceeded or the program terminates.

###Is there a general process flow that can help me understand what's going on?###

Yes. For a complete process flow, refer to the graphic found at [docs/FSF Process.png](https://github.com/EmersonElectricCo/fsf/blob/master/docs/FSF%20Process.png). You may also find a graphic depicting a high level overview helpful as well at [docs/FSF Overview.png] (https://github.com/EmersonElectricCo/fsf/blob/master/docs/FSF%20Overview.png)

###Is there helpful documentation on how to write modules?###

Absolutely. Check out the [docs/modules.md](https://github.com/EmersonElectricCo/fsf/blob/master/docs/MODULES.md) for a great primer on how to get started.

###What kind of modules are written and what do they do?###

The table below provides this information:

|Module|Description|
|---|---|
|SCAN_YARA|Scan incoming object against series of Yara signatures.|
|EXTRACT_EMBEDDED|Use hachoir library to extract embedded files and process them.|
|META_BASIC_INFO|Get basic information about an object to display; size, MD5, sha1, etc...|
|META_PE|Get as much metadata about an EXE file as possible.|
|EXTRACT_ZIP|Get metadata on embedded objects within a ZIP file and extract them.|
|EXTRACT_RAR|Get metadata on embedded objects within a RAR file and extract them.|
|EXTRACT_SWF|Get metadata on embedded objects within a ZWS, CWS, or FWS files and extract them.|
|META_OLECF|Get metadata from OLECF files (legacy Office documents); creation date, modification, author name, etc...|
|META_OOXML|Get metadata from OOXML files (modern Office documents); creation date, modification, author name, etc...|
|META_PDF|Get metadata from PDF files; creation date, modification, author name, etc...|
|EXTRACT_VBA_MACRO|Extract macros from OLE document, scan and capture suspicious attributes.|
|EXTRACT_UPX|Automatically unpack UPX compressed binaries.|
|EXTRACT_RTF_OBJ|Get embedded hexascii objects within RTF files.|
|EXTRACT_GZIP|Get embedded object within a GZIP file and extract it.|
|EXTRACT_TAR|Get metadata on embedded objects within a TAR file and extract them.|
|META_PE_SIGNATURE|Get certificate metadata from PE files.|
|EXTRACT_CAB|Uncompress MS CAB files.|
|META_ELF|Expose metadata within ELF binaries.|
|META_JAVA_CLASS|Expose requirements, capabilities, and other metadata inside Java class files.|
|META_VT_INSPECT|Get VirusTotal info concerning a specific file MD5. (Requires Public or Private API Key)|
|EXTRACT_HEXASCII_PE|Get encoded PE elements out of files and convert to binary.|
|META_MACHO|Exposes the metadata within MACHO binares.|

###How does this scale up if I want to 'scan all the things'?###

The server is parallelized and supports running multiple jobs at the same time. As an example, I've provided one possible way you can accomplish this by integrating with Bro, extracting files, and sending them over to the FSF server. You can find this at the bottom of [docs/modules.md](https://github.com/EmersonElectricCo/fsf/blob/master/docs/MODULES.md) under the heading 'Automated File Extraction'.

Some key advantages to Bro integration are:

* Ability to direct files to a given FSF scanner node on a per sensor basis
* Use of the Bro scripting language to help optimize inputs, some examples might include:
 * Limit sending of a file we've already seen for a certain time interval to avoid redundancy (based on MD5, etc)
 * Limit the size of the file you extracting if desired
 * Control over MIME types you care to pass on to FSF

###What if I want to do load balancing across several FSF servers?###

You can easily integrate different load balancing solutions with FSF if you wish. Doing so, combined with the servers parallel processing for each request has many performance and reliability benefits. It also gives you the flexibility to do load balancing the way you want to, like using equal distribution, grouping, fail over, some combination and more...

For example, you can use the popular utility [Balance](https://www.inlab.de/balance.html) to configure simple load balancing between FSF nodes with one simple command.

`balance -f 5800 10.0.3.5 10.0.3.6`

The above tells balance to run in the foreground on port 5800, and equally distribute requests between the two hosts specified (10.0.3.5 and 10.0.3.6). By default, the requests will be forwarded on port 5800 as well unless otherwise specified. Now we can just point our FSF clients to our load balancer and let it do the work for us.

Of course, you can use a different load balancing solution you'd like, this is just a quick example. You can even specify multiple FSF servers/balancers using the client config file if desired. When doing this, the FSF server chosen for the request is done at random allowing for some rudimentary balancing.


###How can I get access to the subobjects that are recursively processed?###

Ah, so are you tired of using `hachoir-subfile` + `dd` to carve out files during static analysis? Or perhaps running `unzip` or `unrar` to get decompressed files, `upx -d` to get unpacked files, or `OfficeMalScan` to get macros over and over is getting old? 

Well you can certainly use FSF to do the heavy lifting if you'd like. It incorporates the components that make the above tools so helpful into the framework. For other use cases, all you you need is to ensure the intelligence to do what you want is built into the framework (Yara + Module)! Several open source modules included with the package help with this. 

To support analysts submitting files using the client, the --full option will return all the subobjects collected in a new directory.

Word of caution however, make sure you understand how to do it the hard way first!

```
fsf_client.py macro_test --full
...normal report information...
Subobjects of macro_test successfully written to: fsf_dump_1446676465_6ba593d8d5defd6fbaa96a1ef2bc601d
```

If you want to collect sub objects on a grander scale server-side, look into the --archive command. You have five choices that are built-in which allow you to determine how aggressively you want to capture extracted data.

###Okay I think I understand, but I'd like visual representation on what a 'report' looks like?###

Take a look a the following graphic in [docs/Example Test.png](https://github.com/EmersonElectricCo/fsf/blob/master/docs/Example%20Test.png). That represents the file `test.zip` which may be found in [docs/Test.zip](https://github.com/EmersonElectricCo/fsf/blob/master/docs/Test.zip). That file, when recursively processed using FSF outputs what's found in [docs/Test.json](https://github.com/EmersonElectricCo/fsf/blob/master/docs/Test.json).

Each object within this file represents an opportunity to collect/enrich intelligence to drive more informed detections, adversary awareness, correlations, and overall analytical tradecraft.

###There's a lot of JSON output here... What tools exist to help me interact with this data effectively over the command line?###

[Jq](https://stedolan.github.io/jq/) is a great utility to help work with JSON data. You might find yourself wanting to filter out certain modules when reviewing FSF JSON output for intel gain. Please refer to the [docs/jq_examples.md](https://github.com/EmersonElectricCo/fsf/blob/master/docs/JQ_EXAMPLES.md), for some helpful 'FSF specific' examples to accommodate such inquiries. I'd also suggest taking a peek at the [jq Cookbook](https://github.com/stedolan/jq/wiki/Cookbook) for more great examples.

Finally, don't be afraid to check out some of the jq filters we've open sourced as part of the post-processing feature!

Installation
------------

FSF has been tested to work successfully on CentOS and Ubuntu distributions.

Please refer to [docs/INSTALL.md](https://github.com/EmersonElectricCo/fsf/blob/master/docs/INSTALL.md) for a detailed, step-by-step guide on how to get started with either platform.

Alternatively, you can check out our [Dockerfile](https://github.com/EmersonElectricCo/fsf/blob/master/Docker/Dockerfile) if you'd like.

Setup
-----

Check your configuration settings
* __Server-side__ - In [fsf-server/conf/conf.py] (https://github.com/EmersonElectricCo/fsf/blob/master/fsf-server/conf/config.py) 
 * Make sure you are pointing to your master yara signature file using the full path. See [fsf-server/yara/rules.yara] (https://github.com/EmersonElectricCo/fsf/blob/master/fsf-server/yara/rules.yara)
 * Set the logging directory; make sure it exists and ensure you have permissions to write to it
 * In [fsf-server](https://github.com/EmersonElectricCo/fsf/tree/master/fsf-server), start up the server using `./main.py start` and it will daemonize 
* __Client-side__ - In [fsf-client/conf/conf.py](https://github.com/EmersonElectricCo/fsf/blob/master/fsf-client/conf/config.py)
 * Point to your server(s) being used to scan files
 * Submit a file with `fsf_client.py <PATH>`, you can use wildcard for scanning all of the files in a directory

The client may be invoked with the following flags:

```
usage: fsf_client [-h] [--delete] [--source [SOURCE]] [--archive [ARCHIVE]]
                  [--suppress-report] [--full]
                  [file [file ...]]

Uploads files to scanner server and returns the results to the user if
desired. Results will always be written to a server side log file. Default
options for each flag are designed to accommodate easy analyst interaction.
Adjustments can be made to accommodate larger operations. Read the
documentation for more details!

positional arguments:
  file                 Full path to file(s) to be processed.

optional arguments:
  -h, --help           show this help message and exit
  --delete             Remove file from client after sending to the FSF
                       server. Data can be archived later on server depending
                       on selected options.
  --source [SOURCE]    Specify the source of the input. Useful when scaling up
                       to larger operations or supporting multiple input
                       sources, such as; integrating with a sensor grid or
                       other network defense solutions. Defaults to 'Analyst'
                       as submission source.
  --archive [ARCHIVE]  Specify the archive option to use. The most common
                       option is 'none' which will tell the server not to
                       archive for this submission (default). 'file-on-alert'
                       will archive the file only if the alert flag is set.
                       'all-on-alert' will archive the file and all sub
                       objects if the alert flag is set. 'all-the-files' will
                       archive all the files sent to the scanner regardless of
                       the alert flag. 'all-the-things' will archive the file
                       and all sub objects regardless of the alert flag.
  --suppress-report    Don't return a JSON report back to the client and log
                       client-side errors to the locally configured log
                       directory. Choosing this will log scan results server-
                       side only. Needed for automated scanning use cases when
                       sending large amount of files for bulk collection. Set
                       to false by default.
  --full               Dump all sub objects of submitted file to current
                       directory of the client. Format or directory name is
                       'fsf_dump_[epoch time]_[md5 hash of scan results]'.
                       Only supported when suppress-report option is false
                       (default).
```
