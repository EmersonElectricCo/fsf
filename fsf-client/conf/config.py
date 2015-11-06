#!/usr/bin/python
#
# Basic configuration attributes for scanner client.
#

# 'IP Address' is a list. It can contain one element, or more.
# If you put multiple FSF servers in, the one your client chooses will
# be done at random. A rudimentary way to distribute tasks.
SERVER_CONFIG = { 'IP_ADDRESS' : ['127.0.0.1',],
                  'PORT' : 5800 }

# Full path to debug file if run in --not-interactive mode
CLIENT_CONFIG = { 'LOG_FILE' : '/var/log/scanner/client_dbg.log' }
