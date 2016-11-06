"""
Classes and functions for anomaly detection over captured network traffic.
"""
import logging
from sklearn.base import BaseEstimator, ClusterMixin
import pandas as pd
from apache_log_parser import make_parser
import pyshark
from ..base import BaseAnomalyDetector

def preprocess_capture(data, cap_format="pcapng", transp_layer="TCP", capture_filter=""):
    """Gets data in PCAP Ng File Format.
    Returns
    -------
    A dataframe with the parsed data.
    """
    #SEE: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
    if cap_format not in ["pcap", "pcapng"]:
        raise ValueError("format must be pcap or pcapng")
    if transp_layer == "TCP":
        display_filter = "tcp"
    else:
        raise ValueError('transport layer must be TCP')
    capt = pyshark.FileCapture(data, display_filter=display_filter)

    #Temporary list to feed the final DataFrame (Performance)
    tmp = []
    counter = 0
    logging.info("Starting packet processing")
    for pkt in capt:
        filtered = {}
        #First field is a empty string (ignoring)
        for field in pkt["ip"].field_names[1:]:
            #Changing field names for disambiguation in columns
            filtered["ip_"+field] = pkt["ip"].get_field(field)
        for field in pkt["tcp"].field_names[1:]:
            #Changing field names for disambiguation in columns
            filtered["tcp_"+field] = pkt["tcp"].get_field(field)
        tmp.append(filtered)
        counter += 1
        if counter % 1000 == 0:
            logging.info("Processed %d packets", counter)
    logging.info("Ended packet processing")
    logging.info("Converting list to DataFrame")
    X = pd.DataFrame(tmp)
    logging.info("Ended list conversion")
    return X
