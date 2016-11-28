"""
Classes and functions for anomaly detection over webserver log files.
"""

import logging
import string
import urlparse
from scipy.stats import chisquare
from sklearn.base import BaseEstimator, ClusterMixin
import pandas as pd
from apache_log_parser import make_parser
from ..base import BaseAnomalyDetector

def preprocess_requests(data, log_format):
    """Gets data in Common Log File Format (CLF).
    Returns
    -------
    A dataframe with the pased data.
    """
    #SEE: https://www.w3.org/Daemon/User/Config/Logging.html#common-logfile-format
    if log_format == "CLF":
        cols = ["remote_host", "remote_logname", "remote_user",
                "time_received_tz_datetimeobj", "request_http_ver", "request_method",
                "request_url", "status", "response_bytes_clf"]
        parser = make_parser('%h %l %u %t \"%r\" %>s %b')
    elif log_format == "Combined":
        cols = ["remote_host", "remote_logname", "remote_user",
                "time_received_tz_datetimeobj", "request_http_ver", "request_method",
                "request_url", "status", "response_bytes_clf", "request_header_referer",
                "request_header_user_agent"]
        parser = make_parser('%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"')
    else:
        raise ValueError("format must be CLF or Combined")
    #X = pd.DataFrame(columns=cols)
    #Temporary list to feed the final DataFrame (Performance)
    tmp = []
    for line in data:
        parsed = parser(line)
        filtered = {k: v for k, v in parsed.items() if k in cols}
        tmp.append(filtered)
        #X = X.append(filtered, ignore_index=True)
    X = pd.DataFrame(tmp, columns=cols)
    return X

class RequestAnomalyDetector(BaseEstimator, ClusterMixin, BaseAnomalyDetector):
    """Request anomaly detector.
    Parameters
    ----------
   """
    all_ascii = string.join([chr(x) for x in range(256)], '')

    def __init__(self):
        self.attribute_models_ = {}
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
        # Get mean and std
        lengths = X["request_url"].str.len()
        self.attribute_models_["uri_length"] = (lengths.mean(), lengths.std())

        #Verifying character distribution
        char_freq = []
        for i in range(256):
            char_freq.append(0.0)
        count_non_empty = 0
        for index, row in X.iterrows():
            #Ignoring zero length strings / Avoiding division by zero
            if len(row.request_url) == 0:
                continue
            for i in range(256):
                freq = float(row.request_url.count(self.all_ascii[i])) / len(row.request_url)
                char_freq[i] += freq
            count_non_empty += 1
            if index % 1000 == 0:
                logging.info('RequestAnomalyDetector - fit - char dist: Processed %d requests', index)
        for i in range(256):
            char_freq[i] /= count_non_empty
        char_freq.sort(reverse=True)
        #Calculate idealized character distribution (ICD)
        icd = [char_freq[0]]
        icd.append(sum(char_freq[1:4]))
        icd.append(sum(char_freq[4:7]))
        icd.append(sum(char_freq[7:12]))
        icd.append(sum(char_freq[12:16]))
        icd.append(sum(char_freq[16:256]))
        self.attribute_models_["icd"] = icd

        param_sets = []
        for index, row in X.iterrows():
            params = urlparse.parse_qs(urlparse.urlsplit(row.request_url).query)
            if len(params) > 0:
                keys_set = set(params.keys())
                if keys_set not in param_sets:
                    param_sets.append(set(params.keys()))
        self.attribute_models_["param_sets"] = param_sets

        return self

    def predict(self, X):
        """ Checks new data against the normal model.
        Parameters
        ----------
        X: DataFrame, shape (n_samples, n_features).
        Features are characteristics of the requests.
        New data to check.
        """
        result = {}
        #Temporary list to feed the final DataFrame (Performance)
        tmp_lst = []
        try:
            norm_model = self.attribute_models_["uri_length"]
        except AttributeError:
            logging.warning('RequestAnomalyDetector: call to preditct() without previous fit()')
            return None

        for index, row in X.iterrows():
            # TODO: Check more anomaly models
            if len(row.request_url) > norm_model[0] + 2*norm_model[1]:
                tmp_lst.append(True)
            else:
                tmp_lst.append(False)

        anomalous = pd.DataFrame(index=X.index, data=tmp_lst, columns=["uri_length"])
        result["uri_length"] = anomalous.copy()

        tmp_lst = []
        for index, row in X.iterrows():
            char_freq = []
            if len(row.request_url) == 0:
                tmp_lst.append(0.0)
                continue
            for i in range(256):
                char_count = row.request_url.count(self.all_ascii[i])
                char_freq.append(char_count)
            char_freq.sort(reverse=True)
            icd = [char_freq[0]]
            icd.append(sum(char_freq[1:4]))
            icd.append(sum(char_freq[4:7]))
            icd.append(sum(char_freq[7:12]))
            icd.append(sum(char_freq[12:16]))
            icd.append(sum(char_freq[16:256]))

            #Computing x^2 value
            x2_value = chisquare(icd, [self.attribute_models_["icd"][i]*
                                       len(row.request_url) for i in range(6)])
            tmp_lst.append(x2_value.pvalue)
        anomalous = pd.DataFrame(index=X.index, data=tmp_lst, columns=["pvalue"])
        result["pvalue"] = anomalous.copy()

        tmp_lst = []
        for index, row in X.iterrows():
            params = urlparse.parse_qs(urlparse.urlsplit(row.request_url).query)
            detected = False
            if len(params) > 0:
                keys_set = set(params.keys())
                if keys_set not in self.attribute_models_["param_sets"]:
                    detected = True
            tmp_lst.append(detected)
        anomalous = pd.DataFrame(index=X.index, data=tmp_lst, columns=["param_sets"])
        result["param_sets"] = anomalous.copy()

        return result
