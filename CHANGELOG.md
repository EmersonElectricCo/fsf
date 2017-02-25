2/25/2017
----------
* Merged PR#46 which is minor tweak to the misc_hexascii_pe_in_html comments to help avoid some AV vendors flagging the rule file as malware. 

2/09/2017
---------
* Merged PR#43 which moves the pidfile path (formerly hard coded into fsf-server.main) to the fsf-server.conf.config. This allows for more flexible deployment of FSF across multiple platforms. 

2/08/2017
---------

* Merged PR #41 to fix issue #40 where the META_JAVA class was returning a tuple in one of its sub values. This was causing issues with external systems that had strict json interperters. Fix was to convert the tuple to a python dictionary / json sub-document.


1/10/2017
---------

* Moving CLI arg input check for archive type out of the fsf-client module to the main section to make the client code easier to re-use.


12/20/2016
---------

* Added new module META_MACHO - Collect data on Mach-o binaries (thanks zcatbear!)

12/07/2016
---------

* Better error output when an export directory cannot be created or written to.

08/28/2016
---------

* Small bug fix in how connection attempts are made from client. 

08/17/2016
---------

* Merged pull request from spartan782. Allow fail over incase of multiple servers.

07/13/2016
---------

* Small fix to make fsf virtualenv compatible

04/27/2016
----------

* Added new module:
   * EXTRACT_HEXASCII_PE - Snag encoded PE files inside of files (example in source)

* Added new Yara signatures:
   * misc_hexascii_pe_in_html
   * misc_no_dosmode_header

02/11/2016
----------

* Formal 1.0 stable release :)

* Removal of '--interactive' and '--not-interactive' modes from client/server

* Introduction of new flags to the client to support more flexibility 
	* Added '--source', to specify the source of the input. Useful when scaling up to larger operations or supporting multiple sources; such as integrating with a sensor grid or other network defense solutions. Defaults to 'Analyst' as submission source
	* Added '--delete' to remove file from client after sent to FSF server. Data can be archived later on server depending on selected options
	* Added '--archive' to specify how the file submission should be stored on the server (if at all)
		* The most common option is 'none' which will tell the server not to archive for this submission (default)
		* 'file-on-alert' will archive the file only if the alert flag is set
		* 'all-on-alert' will archive the file and all sub objects if the alert flag is set
		* 'all-the-files' will archive all the files sent to the scanner regardless of the alert flag
		* 'all-the-things' will archive the file and all sub objects regardless of the alert flag
	* Added '--suppress-report', don't return a JSON report back to the client and log client-side errors to the locally configured log directory. Choosing this will log scan results server-side only. Needed for automated scanning use cases when sending large amount of files for bulk collection. Set to false by default.

* Updated documentation:
	* New process flow diagram to reflect changes
	* New overview picture to get rid of old 'interactive modes'
	* Updated [modules](https://github.com/EmersonElectricCo/fsf/blob/master/docs/MODULES.md) to reflect removal of 'interactive' modes and addition of new flags
	* Added a few usage notes to the readme based on the recent changes
		* fsf_client -h output
	* Added a module matrix to give an overview of capabilities

02/03/2016
----------
* Docker image updated (thanks wzod!)

02/01/2016
----------

* Updated documentation:
	* README update to include post-processing capability
	* Added documentation on incorporating jq filters for post-processing (JQ_FILTERS.md)
	* Updated FSF process diagram
	* Updated install documents to include new requirements:
		* Python modules: pyelftools, javatools, requests
		* Tools: jq

* Introduced the addition of report post processing capability using jq filters!
	* Observations informed by jq filters are now added to the FSF report summary
	* Check out the [documentation](https://github.com/EmersonElectricCo/fsf/blob/master/docs/JQ_FILTERS.md)

* Added new modules:
	* META_ELF - Extract metadata contents inside ELF files
	* META_JAVA_CLASS - Expose requirements, capabilities, and other metadata inside Java class files
	* META_VT_INSPECT - Query VT for AV assessment on various files (public/private API key required)

* Bug fixes:
	* Spacing issue with a few lines in fsf_client.py
	* UnicodeDecodeError with some kinds of macro files, adjusted EXTRACT_VBA_MACRO to accommodate

* Added some starter jq filters:
	* embedded_sfx_rar_w_exe.jq  
	* macro_gt_five_suspicious.jq  
	* no_yara_hits.jq          
	* vt_broadbased_detections_found.jq  
	* vt_match_not_found.jq
	* exe_in_zip.jq              
	* many_objects.jq              
	* one_module.jq            
	* vt_exploit_detections_found.jq
	* fresh_vt_scan.jq           
	* more_than_ten_yara.jq        
	* pe_recently_compiled.jq  
	* vt_match_found.jq

* Added new Yara signatures:
	* ft_elf.yara
	* ft_java_class.yara

01/09/2016
----------
* Docker image updated (thanks wzod!)

01/08/2016
----------

* Updated installation docs to include cabextract and latest pefile module

* Added new module:
	* EXTRACT_CAB - Extract contents and metadata of MS CAB files. Requires installation of cabextract utility

* Improved some modules:
	* META_PE - Now includes metadata for the entry point, image base, and import hash. Requires latest pefile module (>= 1.2.10-139)
	* META_BASIC_INFO - Made this an ordered dictionary for display reasons

* Core changes to address some minor bugs.
	* Added server side timeout condition in off chance where client terminates connection mid transfer
	* Added small sanity check to verify input is from a true FSF client 

* Added new Yara signatures:
	* ft_cab.yara
	* ft_jar.yara

11/23/2015
----------

* NOTE - please ensure you have the OpenSSL development libraries installed (openssl-devel for RH distros, libssl-dev for Debian) before installing Yara. Otherwise signatures like the newly added `misc_pe_signature.yara` will not work! If you don't have these, please install them and then reinstall Yara. This has been captured in [Yara Issue #378](https://github.com/plusvic/yara/issues/378).

* Updated installation requirements to include Python modules pyasn1 and pyasn1-modules. This is necessary to use META_PE_SIGNATURE.

* Added new modules:
 * EXTRACT_RTF_OBJ - Get embedded, hexascii encoded, OLE objects within RTFs.
 * EXTRACT_TAR - Get metadata and embedded objects within a TAR file and extract them. Some interesting goodies in TAR metadata, you should check it out!
 * EXTRACT_GZIP - Get embedded file within GZIP archive and extract it
 * META_PE_SIGNATURE - Get certificate metadata from PE files. Long overdue and really useful I hope!

* Improved some modules:
 * META_PE - Now delivers information on PE imports and export entries as appropriate, also provides version info 
 * EXTRACT_ZIP - More generous on corrupt ZIP files. It will now process embedded archives the best it can, if one is corrupt, it will move to the next instead of failing entirely
 * EXTRACT_RAR - Removed StringIO module in imports, was unnecessary

* Added a section on jq tippers for help interacting FSF JSON output in docs
 * Filter out multiple nodes from JSON output
 * Show results from only one module
 * Contribute your own creative jq-fu!

* Updated Test.json to accommodate output from module additions

* Updated README.md with notes on jq use with FSF data

* Added new Yara signatures:
 * ft_gzip.yara
 * ft_rtf.yara
 * ft_tar.yara
 * misc_pe_signature.yara

* Docker image updated (thanks wzod!)

11/09/2015
----------
* Added detailed step-by-step installation instructions for Ubuntu and CentOS platforms. (thanks for the nudge cfossace!)

11/06/2015
----------
* Docker image updated (thanks wzod!)

11/05/2015
----------
* Changes to core code to accomodate the following:
 * Point client to more than one FSF server if desired
 * Added option for analyst to dump all subobjects returned to client
 * Added summary key value pairs for list of unique Yara signature hits as well as modules run with results. Helps to better digest output.

* Added new modules:
 * EXTRACT_UPX - Unpack upx packed binaries
 * EXTRACT_VBA_MACRO - Extract and scan macro for anomolies to include in report using oletools.olevba module

* Added new Yara sig:
 * misc_upx_packed_binary.yara

* Documentation updates:
 * Updated module howto and readme documentation to incorporate recent core changes
 * Added visual graphic of test.zip along with sample file and JSON output to help with understanding

10/14/2015
----------
* Minor grammar and usage clarifications (thanks mkayoh!)

09/28/2015
----------
* Docker image added (thanks wzod!)

08/28/2015
----------
* Added new modules:
 * EXTRACT_EMBEDDED - if hachoir subfile detects embedded content, rip it out and feed it back in for scanning
 * EXTRACT_SWF - return basic metadata about SWF, but also deflate LZMA or ZLib compressed SWF files
 * META_OLECF - Return basic metadata concerning an OLE document (hachoir again for the heavy lifting)
 * META_OOXML - Parse the core.xml file for various properties of a file
 * META_PDF - Return basic metadata on PDF files

* Added new Yara sigs:
 * ft_office_open_xml.yara
 * ft_ole_cf.yara
 * ft_pdf.yara
 * ft_swf.yara
 * misc_compressed_exe.yara
 * misc_ooxml_core_properties.yara

08/05/2015
----------
* Initial commit
