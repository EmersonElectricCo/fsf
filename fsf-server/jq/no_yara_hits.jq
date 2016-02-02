# Author: Jason Batchelor
# Company: Emerson
# Description: Simple JQ to see if no Yara signatures hit.

.Summary.Yara | length == 0
