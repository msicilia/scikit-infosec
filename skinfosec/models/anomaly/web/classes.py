from ..base import BaseAnomalyDetector
from sklearn.base import BaseEstimator, ClusterMixin
import pandas as pd
from apache_log_parser import make_parser
import logging

def preprocess_requests(data, format="CLF"):
    """Gets data in Common Log File Format (CLF).
    Returns
    -------
    A dataframe with the pased data.
    """
    #SEE: https://www.w3.org/Daemon/User/Config/Logging.html#common-logfile-format
    if format == "CLF":
        cols=["remote_host", "remote_logname", "remote_user",
               "time_received_tz_datetimeobj", "request_http_ver", "request_method",
               "request_url", "status", "response_bytes_clf"]
        parser = make_parser('%h %l %u %t \"%r\" %>s %b')
    elif format == "Combined":
        cols=["remote_host", "remote_logname", "remote_user",
               "time_received_tz_datetimeobj", "request_http_ver", "request_method",
               "request_url", "status", "response_bytes_clf", "request_header_referer",
               "request_header_user_agent"]
        parser = make_parser('%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"')
    else:
         raise ValueError("format must be CLF or Combined")
    X = pd.DataFrame(columns=cols)
    for line in data:
        parsed = parser(line)
        filtered = {k: v for k, v in parsed.items() if k in cols}
        #print filtered
        X = X.append(filtered, ignore_index=True)
    return X

class RequestAnomalyDetector(BaseEstimator, ClusterMixin,
                             BaseAnomalyDetector):
    """Request anomaly detector.
    Parameters
    ----------
   """
    def __init__(self):
        return

    def fit(self, X, y=None):
        """ Create normal model for Web requests.
        Parameters
        ----------
        X: DataFrame, shape (n_samples, n_features).
        Features are characteristics of the requests.
        """
        #TODO: Add other attributes of Web traffic.
        # Now it checks only URL length.
        self.attribute_models_={}
        # Get mean and std
        lengths = X["request_url"].str.len()
        self.attribute_models_["uri_length"] = (lengths.mean(), lengths.std())
        return self

    def predict(self, X):
        """ Checks new data against the normal model.
        Parameters
        ----------
        X: DataFrame, shape (n_samples, n_features).
        Features are characteristics of the requests.
        New data to check.
        """
        anomalies = {}
        anomalous = pd.DataFrame()
        try:
            norm_model = self.attribute_models_["uri_length"]
        except AttributeError:
            logging.warning('RequestAnomalyDetector: call to preditct() without previous fit()')
            return anomalies
        for index, row in X.iterrows():
            # TODO: Check more anomaly models
            if len(row.request_url) > norm_model[0] + 2*norm_model[1]:
                anomalous = anomalous.append(row)
        anomalies["uri_length"] = anomalous
        return anomalies
