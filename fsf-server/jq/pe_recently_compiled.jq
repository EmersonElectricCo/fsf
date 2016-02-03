# Author: Jason Batchelor
# Company: Emerson
# Description: Check if output contains EXE compiled in the past week.

(now - 604800) < (map(..|.META_PE?.Compiled|select(. != null)) | .[] | strptime("%a %b %d %H:%M:%S %Y UTC") | mktime)
