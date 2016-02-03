# Author: Jason Batchelor
# Company: Emerson
# Description: Check to see of no VT matches were observed when queried
map(..|.META_VT_INSPECT?|.response_code|select(type=="number")) | all (. == 0) and length > 0
