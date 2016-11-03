from skinfosec.models.anomaly.packet_capture import classes

import logging
from timeit import default_timer as timer

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

from skinfosec.models.anomaly.packet_capture.tests import test_capture_anomaly_detector
test_capture_anomaly_detector.test_preprocess_capture()
