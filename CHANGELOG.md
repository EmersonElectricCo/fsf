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
