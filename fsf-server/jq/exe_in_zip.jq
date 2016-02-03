# Author: Jason Batchelor
# Company: Emerson
# Description: Check if a ZIP contains an EXE

path(..) | join(" "?) | match("EXTRACT_ZIP Object_.*? SCAN_YARA ft_exe") | .length > 0
