# fsf
File Scanning Framework
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

This decision is left up to you since there are many ways to do this.
* Write a module to email your team if the alert flag is set
* Aggregate and index the scan.log data to a utility like Splunk and define a rule within that

###Is there a way I can take action on a specific rule hit from within the FSF? Like print out metadata for certain file types?###

This is precisely what modules are for! Module development driven by analyst observations is a cornerstone of the FSF!

###This is pretty cool – but I don’t really know that much about Yara?###

Check out the [Yara official documentation](http://yara.readthedocs.org/) for more information and examples.

###What are the tools limitations?###

* Since we recursively process objects, a `MIN_DEPTH` configurable value is enforced.
* There is a `TIMEOUT` value that is imposed on each module run that may not be exceeded or the program terminates.

Requrements
------------

FSF has been tested to work successfully on CentOS and Ubuntu distributions.

Below are steps to setup on CentOS and should be adaptable to other distributions.
* Update with latest default packages
* Install Yara and Yara Python module
 * Make sure you can import the Python Yara module! Sometimes you need to manually add the library path in `/etc/ld.so.conf.d`.
* Turn on the EPEL repo 
 * yum install epel-release
* Install following rpm packages (yum install)
 * python-argparse python-devel python-pip ssdeep-devel libffi-devel
* Install unrar from RPM repo such as DAG
		
* Install module dependencies
 * `easy_install -U setuptools`
 * `pip install czipfile pefile hachoir-parser hachoir-core hachoir-regex hachoir-metadata hachoir-subfile ConcurrentLogHandler pypdf2 xmltodict rarfile ssdeep pylzma`

Setup
-----

Check your configuration settings
* __Server side__ - In [https://github.com/EmersonElectricCo/fsf/blob/master/fsf-server/conf/config.py](fsf-server/conf/conf.py) 
 * Make sure you are pointing to your master yara signature file using the full path. See [https://github.com/EmersonElectricCo/fsf/blob/master/fsf-server/yara/rules.yara](fsf-server/yara/rules.yara)
 * Set the logging directory; make sure it exists and ensure you have permissions to write to it
 * In [https://github.com/EmersonElectricCo/fsf/tree/master/fsf-server](fsf-server), start up the server using `./main.py start` and it will daemonize 
* __On client__ - In [https://github.com/EmersonElectricCo/fsf/blob/master/fsf-client/conf/config.py](fsf-client/conf/conf.py)
 * Point to your server being used to scan files
 * Invoke `fsf-client.py` by giving it a file as an argument
