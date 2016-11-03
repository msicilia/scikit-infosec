"""
Tests for the request anomaly detection model.
"""

import logging
from ..classes import preprocess_capture

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

def test_preprocess_capture():
    """Tests with a simple pcap-ng capture
    """
    X = preprocess_capture("capture.pcapng")
    X.fillna(0, inplace=True)
    print X.head()
    print X.axes
