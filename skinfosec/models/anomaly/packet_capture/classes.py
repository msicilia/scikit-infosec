"""
Classes and functions for anomaly detection over captured network traffic.
"""
import logging
from sklearn.base import BaseEstimator, ClusterMixin
import pandas as pd
from apache_log_parser import make_parser
import pyshark
from ..base import BaseAnomalyDetector

def preprocess_capture(data, ip_version=4, transp_layer="TCP"):
    """Parsess packet capture files (pcap or pcap-ng).

    Args:
        data: File path for capture file.
        log_format: Either "CLF" or "Combined".

    Returns:
        pandas.DataFrame with the parsed data.

    """
    #SEE: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html

    #TODO Implement ipv6, udp and ICMP
    if ip_version == 4:
        pass
    else:
        raise ValueError('IP version must be "4"')

    if transp_layer == "TCP":
        pass
    else:
        raise ValueError('transport layer must be TCP')

    try:
        capt = pyshark.FileCapture(data, keep_packets=False, display_filter='tcp')
    except:
        exit("Could not open pcap file")

    ip_fields = ['src', 'dst', 'flags_df', 'flags_mf', 'hdr_len', 'len', 'ttl']
    tcp_fields = ['srcport', 'dstport', 'flags_ack', 'flags_fin', 'flags_push',
                  'flags_reset', 'flags_syn', 'flags_urg', 'hdr_len', 'len']

    #Temporary list to feed the final DataFrame (Performance)
    tmp = []
    counter = 0
    logging.info("Starting packet processing")
    for pkt in capt:
        filtered = {}
        #First field is a empty string (ignoring)
        if hasattr(pkt, 'ip'):
            for field in ip_fields:
                #Changing field names for disambiguation in columns
                filtered["ip_"+field] = pkt["ip"].get_field(field)
        else:
            continue
        if hasattr(pkt, 'tcp'):
            for field in tcp_fields:
                #Changing field names for disambiguation in columns
                filtered["tcp_"+field] = pkt["tcp"].get_field(field)
        else:
            continue
        tmp.append(filtered)
        counter += 1
        if counter % 1000 == 0:
            logging.info("Processed %d packets", counter)
    logging.info("Ended packet processing")
    logging.info("Converting list to DataFrame")
    X = pd.DataFrame(tmp)
    logging.info("Ended list conversion")
    return X
