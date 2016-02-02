# Author: Jason Batchelor
# Company: Emerson
# Description: More than five suspicious macro attributes

map(..|.EXTRACT_VBA_MACRO?|..|.Suspicious?|select(. != null)| length > 5) | .[]
