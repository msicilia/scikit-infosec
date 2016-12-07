from skinfosec.models.anomaly.web.classes import RequestAnomalyDetector
from skinfosec.models.anomaly.web import classes
import logging
from timeit import default_timer as timer

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

logFile = "access.log"
#logFile = "access-extended-short.log"
logFH = open(logFile)

#X = classes.preprocess_requests(logFH, log_format="Combined")
X = classes.preprocess_requests(logFH,"CLF")

start = timer()
ad = RequestAnomalyDetector()
ad.fit(X)

anomalies = ad.predict(X)

print(anomalies)
#anon_uri_len = anomalies['uri_length']
print(anomalies.loc[anomalies['uri_length'] == 1])

end = timer()
print(end - start)
