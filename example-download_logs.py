import logging
from sklearn.cluster import KMeans
from skinfosec.datasets import chuvakin_httpd
from skinfosec.models.anomaly.web.classes import RequestAnomalyDetector
from skinfosec.models.anomaly.web import classes

from timeit import default_timer as timer
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

start = timer()
X = chuvakin_httpd.fetch_chuvakin_logs()

start = timer()
ad = RequestAnomalyDetector()
ad.fit(X)

anomalies = ad.predict(X)

print(anomalies)
#anon_uri_len = anomalies['uri_length']
print(anomalies.loc[anomalies['uri_length'] == 1])

end = timer()
print(end - start)
