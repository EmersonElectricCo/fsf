# Author: Jason Batchelor
# Company: Emerson
# Description: Check if an embedded file contained a RAR, which itself contained an EXE

path(..) | join(" "?) | match("EXTRACT_EMBEDDED Object_.*? EXTRACT_RAR Object_.*? SCAN_YARA ft_exe") | .length > 0
