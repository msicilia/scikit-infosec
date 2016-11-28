#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Fri Nov 25 12:57:01 2016

@author: migueld
"""

from cwe import CWE

url = "cwec_v2.9.xml"
cwe = CWE(url)
print(cwe["200"].to_string())