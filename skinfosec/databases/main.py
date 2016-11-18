#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Wed Nov 16 09:45:17 2016

@author: migueld
"""
from cve import CVE


url = 'nvdcve-2.0-2002.xml.gz'

cve = CVE(url, False)
b = cve["CVE-1999-0001"]
    