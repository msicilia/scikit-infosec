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


ad = RequestAnomalyDetector()
start = timer()
ad.fit(X)
end = timer()
print("fit elapsed time = ",end - start)

start = timer()
anomalies = ad.predict(X)
end = timer()
print("predict elapsed time = ",end - start)

print(anomalies)
anon_uri_len = anomalies['uri_length']
print(anomalies.loc[anomalies['uri_length'] == 1])
start = timer()
ad.kmeans()
print(ad.kmeans_labels)
end = timer()
print("kmeans elapsed time = ",end - start)

end = timer()
print(end - start)
