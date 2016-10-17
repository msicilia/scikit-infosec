"""
Tests for the request anomaly detection model.
"""
from ..classes import preprocess_requests
from ..classes import RequestAnomalyDetector

def test_preprocess_requests():
    """Tests with a simple CLF log
    """
    example = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
    X = preprocess_requests([example])
    #TODO: Include assertions for all fields.
    assert(X.request_url[0] == "/apache_pb.gif")

def test_anomaly_detector():
    """Test the anomaly detector
    """
    ad = RequestAnomalyDetector()
    with open("access.log") as f:
        content = f.readlines()
    X = preprocess_requests(content)
    ad = ad.fit(X)
    anomalies = ad.predict(X)
    print anomalies["uri_length"].head()
    assert(False)
