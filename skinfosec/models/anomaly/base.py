"""
Base Module for Anomay Detector Classes
"""
from datetime import datetime

class BaseAnomalyDetector(object):
    """Base Class for Anomay Detector Classes"""
    def __init__(self):
        self.date_created = datetime.now()
