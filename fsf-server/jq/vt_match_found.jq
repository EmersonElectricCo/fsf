# Author: Jason Batchelor
# Company: Emerson
# Description: Check of VT query contained a match at some level.

map(..|.META_VT_INSPECT?|.response_code) | del(.[] | nulls) | unique | .[] > 0
