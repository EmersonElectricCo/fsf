# Author: Jason Batchelor
# Company: Emerson
# Description: Simple JQ to see if more than ten Yara signatures hit on something.

.Summary.Yara | length > 10
