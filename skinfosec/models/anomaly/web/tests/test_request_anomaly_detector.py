"""
Tests for the request anomaly detection model.
"""
from ..classes import preprocess_requests
from ..classes import RequestAnomalyDetector

def test_preprocess_requests():
    """Tests with a simple CLF log
    """
    example = ('127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET '
               '/apache_pb.gif HTTP/1.0" 200 2326')
    X = preprocess_requests([example])
    assert X.remote_host[0] == "127.0.0.1"
    assert X.remote_logname[0] == "-"
    assert X.remote_user[0] == "frank"
    #time_received_tz_datetimeobj type is pandas.tslib.Timestamp
    assert (X.time_received_tz_datetimeobj[0].to_pydatetime().strftime(
        "%d/%b/%Y:%H:%M:%S") == "10/Oct/2000:20:55:36")
    assert X.request_http_ver[0] == "1.0"
    assert X.request_method[0] == "GET"
    assert X.request_url[0] == "/apache_pb.gif"
    assert X.status[0] == "200"
    assert X.response_bytes_clf[0] == "2326"

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
    assert False
