File Scanning Framework (FSF)
==============

Introduction
------------

###What is the ‘file scanning framework’?###

The FSF is a modular solution that enables analysts to extend the utility of the Yara signatures they write and define actionable intelligence within a file. This is accomplished by recursively scanning a file and looking for opportunities to extract file objects using a combination of Yara signatures (to define opportunities) and programmable logic (to define what to do with the opportunity).
The framework allows you to build out your intelligence capability by empowering you to apply observations wrought out of the analytical process…

Okay that’s a mouthful – but think about it – if you see that some pattern (maybe a string or a byte sequence) that represents some concept or behavior; through the use of the framework, you are positioned to capture that observation and apply it to certain file types that meet your criteria.

Some examples might be:
* Uncompressing ZIP files and scanning their contents.
* Decoding a malware config file that matches a specific signature, then parsing the meta data.
* General metadata enrichment for any file type.
 * Logging the compile time for any EXE
 * Logging the author field for office documents
 * So much more...

You can extend and define what’s important by writing modules that expose pieces of metadata that inform analysis and expose new sub objects of a file! These sub objects are recursively scanned through the same gauntlet, further enhancing both Yara and module utility.

###If we alert on a signature, how will we know?###

This decision is left up to you since there are many ways to do this. One suggestion might be to aggregate and index the scan.log data using something like [Splunk](http://www.splunk.com/) or with an [ELK Stack](http://brewhouse.io/blog/2014/11/04/big-data-with-elk-stack.html). You can then build your alerting into the capability.

###Is there a way I can take action on a specific rule hit from within the FSF? Like print out metadata for certain file types?###

This is precisely what modules are for! Module development driven by analyst observations is a cornerstone of the FSF!

###This is pretty cool – but I don’t really know that much about Yara?###

Check out the [Yara official documentation](http://yara.readthedocs.org/) for more information and examples.

###What are the tools limitations?###

* Since we recursively process objects, a `MIN_DEPTH` configurable value is enforced.
* There is a `TIMEOUT` value that is imposed on each module run that may not be exceeded or the program terminates.

###Is there a general process flow that can help me understand what's going on?###

Yes. For a complete process flow, refer to the graphic found at [docs/FSF Process.png](https://github.com/EmersonElectricCo/fsf/blob/master/docs/FSF%20Process.png). You may also find a graphic depicting a high level overview helpful as well at [docs/FSF Overview.png] (https://github.com/EmersonElectricCo/fsf/blob/master/docs/FSF%20Overview.png)

###Is there helpful documentation on how to write modules?###

Absolutely. Check out the [docs/modules.md](https://github.com/EmersonElectricCo/fsf/blob/master/docs/MODULES.md) for a great primer on how to get started.

###How does this scale up if I want to 'scan all the things'?###

The server is parallelized and supports running multiple jobs at the same time. As an example, I've provided one possible way you can accomplish this by integrating with Bro, extracting files, and sending them over to the FSF server. You can find this at the bottom of [docs/modules.md](https://github.com/EmersonElectricCo/fsf/blob/master/docs/MODULES.md) under the heading 'Automated File Extraction'.

Some key advantages to Bro integration are:

* Ability to direct files to a given FSF scanner node on a per sensor basis
* Use of the Bro scripting language to help optimize inputs, some examples might include:
 * Limit sending of a file we've already seen for a certain time interval to avoid redundancy (based on MD5, etc)
 * Limit the size of the file you extracting if desired
 * Control over MIME types you care to pass on to FSF

###How can I get access to the subobjects that are recursively processed?###

Ah, so are you tired of using `hachoir-subfile` + `dd` to carve out files during static analysis? Or perhaps running `unzip` or `unrar` to get decompressed files, `upx -d` to get unpacked files, or `OfficeMalScan` to get macros over and over is getting old? 

Well you can certainly use FSF to do the heavy lifting if you'd like. It incorporates the components that make the above tools so helpful into the framework. For other use cases, all you you need is to ensure the intelligence to do what you want is built into the framework (Yara + Module)! Several open source modules included with the package help with this. Just use the --full option when invoking the client and all the subobjects will collect in a new directory.

Word of caution however, make sure you understand how to do it the hard way first!

```
fsf-client macro_test --full
...normal report information...
Subobjects of macro_test successfully written to: fsf_dump_1446676465_6ba593d8d5defd6fbaa96a1ef2bc601d
```

###Okay I think I understand, but I'd like visual representation on what a 'report' looks like?###

Take a look a the following graphic in [docs/Example Test.png](https://github.com/EmersonElectricCo/fsf/blob/master/docs/Example%20Test.png). That represents the file `test.zip` which may be found in [docs/Test.zip](https://github.com/EmersonElectricCo/fsf/blob/master/docs/Test.zip). That file, when recursively processed using FSF outputs what's found in [docs/Test.json](https://github.com/EmersonElectricCo/fsf/blob/master/docs/Test.json).

Each object within this file represents an opportunity to collect/enrich intelligence to drive more informed detections, adversary awareness, correlations, and overall analytical tradecraft.

###There's a lot of JSON output here... What tools exist to help me interact with this data effectively over the command line?###

[JQ](https://stedolan.github.io/jq/) is a great utility to help work with JSON data. You might find yourself wanting to filter out certain modules when reviewing FSF JSON output for intel gain. Please refer to the [docs/JQ_Examples.md](https://github.com/EmersonElectricCo/fsf/blob/master/docs/JQ_Examples.md), for some helpful 'FSF specific' examples to accommodate such inquiries. I'd also suggest taking a peek at the [JQ Cookbook](https://github.com/stedolan/jq/wiki/Cookbook) for more great examples.

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
 * Submit a file with `fsf-client.py <PATH>`, you can use wildcard for scanning all of the files in a directory
