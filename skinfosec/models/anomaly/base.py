from datetime import datetime

class BaseAnomalyDetector:
    def __init__(self):
        self.date_created = datetime.now()
