# Author: Jason Batchelor
# Company: Emerson
# Description: Inspect AV output for trace elements of PUP detection names
map(..|.META_VT_INSPECT?.scans|.[]?.result|select(. != null)) | join(" ") | test("Riskware|PUP|Adware|Toolbar")
