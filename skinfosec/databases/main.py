#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Wed Nov 16 09:45:17 2016

@author: migueld
"""
from cve import CVE
import pandas as pd

url_download = 'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2003.xml.gz'
url = 'nvdcve-2.0-2003.xml.gz'

# cve = CVE(url_download, True, False)
  
final_df = pd.DataFrame()

for i in range(2002, 2017):
    print(i)
    url_download = 'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-'+str(i)+'.xml.gz'
    cve = CVE(url_download, True, False)
    df = cve.to_df()
    final_df.append(df)
    
