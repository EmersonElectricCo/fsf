# Author: Jason Batchelor
# Company: Emerson
# Description: Check if an FSF run produced more than ten unique objects

map(..|.SHA256?)| del(.[] | nulls) | unique | length >= 10
