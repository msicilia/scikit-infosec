from skinfosec.models.anomaly.web.classes import RequestAnomalyDetector
from skinfosec.models.anomaly.web import classes

import logging
from timeit import default_timer as timer

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

logFile = "access.log"  # Should be some file on your system
#logFile = "access-extended-short.log"  # Should be some file on your system
logFH = open(logFile)

start = timer()
ad = RequestAnomalyDetector()
#X = classes.preprocess_requests(logFH, log_format="Combined")
X = classes.preprocess_requests(logFH,"CLF")
#print X.axes

ad.fit(X)
#ad.predict(X)
anomalies = ad.predict(X)
print anomalies
#print anomalies.loc[anomalies['uri_length'] == True]
#print anomalies["uri_length"].head()

#from skinfosec.models.anomaly.web.tests import test_request_anomaly_detector

#test_request_anomaly_detector.test_preprocess_requests()
#test_request_anomaly_detector.test_anomaly_detector()

end = timer()
print end - start
