# Author: Jason Batchelor
# Company: Emerson
# Description: Signature to see if any VT results contain submissions less than 24 hours old.

(now - 86400) < (map(..|.META_VT_INSPECT?.scan_date|select(. != null)) | .[] | strptime("%Y-%m-%d %H:%M:%S") | mktime)
