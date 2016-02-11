#!/usr/bin/python
#
# This is the Python 'module' that contains the 
# disposition criteria for Yara and jq filters the scanner framework
# will work on. Each member is the name of a 
# high fidelity detection.
#
# default - Modules that are always run on a returned buffer value
# triggers - List of tuples that are configured to drive the flow of execution
# as the file itself it scanned recursively. They consist of Yara rule names
# that (if evaluated to true) may then run zero, one or more modules and optionally
# set the alert flag.
# post_processor - List of tuples that are configured to capture observations
# concerning the JSON output. These consist of jq filters that ultimately produce
# a boolean value dictating if a given condition is true. If 'true' then the 
# observation is captured and the alert flag is optionally set. 
default = ['META_BASIC_INFO',
           'EXTRACT_EMBEDDED',
           'SCAN_YARA']

# STRUCTURE: List of tuples such that...
# Types:  [('string', 'list', boolean'), ...]
# Variables: [('rule name', ['module_1' , 'module_2'] , 'alert_flag'), ...]
triggers = [('ft_zip', ['EXTRACT_ZIP'], False),
            ('ft_exe', ['META_PE'], False),
            ('ft_rar', ['EXTRACT_RAR'], False),
            ('ft_ole_cf', ['META_OLECF', 'EXTRACT_VBA_MACRO'], False),
            ('ft_pdf', ['META_PDF'], False),
            ('misc_ooxml_core_properties', ['META_OOXML'], False),
            ('ft_swf', ['EXTRACT_SWF'], False),
            ('misc_upx_packed_binary', ['EXTRACT_UPX'], False),
            ('ft_rtf', ['EXTRACT_RTF_OBJ'], False),
            ('ft_tar', ['EXTRACT_TAR'], False),
            ('ft_gzip', ['EXTRACT_GZIP'], False),
            ('misc_pe_signature', ['META_PE_SIGNATURE'], False),
            ('ft_cab', ['EXTRACT_CAB'], False),
            ('ft_elf', ['META_ELF'], False),
            ('ft_java_class', ['META_JAVA_CLASS'], False),
     ]

# STRUCTURE: List of tuples such that...
#  Types:      [('string', 'string', boolean'), ...]
#  Variables:  [('jq script', 'observation' , 'alert_flag'), ...]
post_processor = [('one_module.jq', 'Only one kind of module was run on for this report.', False),
                  ('no_yara_hits.jq', 'There doesn\'t appear to be any Yara signature hits for this scan.', False),
                  ('exe_in_zip.jq', 'An executable was found inside a ZIP file.', False),
                  ('embedded_sfx_rar_w_exe.jq', 'An embedded file contained a self-extracting RAR that itself contained an executable payload.', False),
                  ('many_objects.jq', 'More than 10 unique objects were observed in this file.', False),
                  ('vt_match_found.jq', 'At least one file was found to have results in VirusTotal\'s database.', False),
                  ('vt_match_not_found.jq', 'There were no matches found when VirusTotal was queried.', False),
                  ('macro_gt_five_suspicious.jq', 'A macro was found with more than five suspicious traits.', False),
                  ('vt_broadbased_detections_found.jq', 'Some AV products have detected this as a PUP threat.', False),
                  ('vt_exploit_detections_found.jq', 'Some AV products have detected this as an exploit.', False),
                  ('more_than_ten_yara.jq', 'More than 10 unique Yara signatures fired when processing this file!', False),
                  ('fresh_vt_scan.jq', 'One of the VirusTotal results contains an object that was scanned less than 24 hours ago.', False),
                  ('pe_recently_compiled.jq', 'An executable has a compile time less than a week old.', False),
                 ]
