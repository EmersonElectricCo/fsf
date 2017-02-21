#! /usr/bin/env python
#
"""
@author: Adam Kniffen
@contact: adamkniffen@gmail.com
@copyright: Copyright 2017
@organization: MOCYBER
@status: Development
"""

import sys

def scan_log(raw_report):
    """
    This just returns the raw_report--it acts like the default FSF logger
    :param raw_report: type:dict, the FSF Scan report
    :return: type:dict, an unmolested FSF Scan report
    """
    return raw_report

if __name__ == "__main__":
    print scan_log(raw_report=sys.stdin.read())
