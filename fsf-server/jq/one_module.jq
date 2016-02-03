# Author: Jason Batchelor
# Company: Emerson
# Description: Simple JQ to see if only one module was kicked off.

.Summary.Modules | length == 1
