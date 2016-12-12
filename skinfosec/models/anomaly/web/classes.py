"""
Classes and functions for anomaly detection over webserver log files.
"""

import logging
#import string
import urllib.parse as urlparse
from scipy.stats import chisquare
from sklearn.base import BaseEstimator, ClusterMixin
from sklearn.cluster import KMeans
import pandas as pd
from apache_log_parser import make_parser
from ..base import BaseAnomalyDetector

def preprocess_requests(data, log_format):
    """Gets logs in NCSA Common Log Format (CLF) or NCSA Combined.

    Args:
        data: File handle for log file.
        log_format: Either "CLF" or "Combined".

    Returns:
        pandas.DataFrame with the parsed data.

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

    #Temporary list to feed the final DataFrame (for better performance)
    log_lst = []
    for line in data:
        parsed = parser(line)
        filtered = {k: v for k, v in parsed.items() if k in cols}
        log_lst.append(filtered)
    X = pd.DataFrame(log_lst, columns=cols)
    return X

class RequestAnomalyDetector(BaseEstimator, ClusterMixin, BaseAnomalyDetector):
    """Request anomaly detector.
    Parameters
    ----------
   """
    all_ascii = ''.join([chr(x) for x in range(256)])

    def __init__(self):
        self.attribute_models_ = {}
        self.kmeans_labels = None
        return

    def fit(self, X, y=None):
        """ Create normal model for Web requests.
        Parameters
        ----------
        X: DataFrame, shape (n_samples, n_features).
        Features are characteristics of the requests.
        """
        #TODO: Add other attributes of Web traffic.
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

        ##Verifying distinct sets and lists of parameters
        param_sets = []
        param_lists = []
        for index, row in X.iterrows():
            params = urlparse.parse_qs(urlparse.urlsplit(row.request_url).query)
            if len(params) > 0:
                keys_set = set(params.keys())
                if keys_set not in param_sets:
                    param_sets.append(set(params.keys()))
            params = urlparse.parse_qsl(urlparse.urlsplit(row.request_url).query)
            param_list = [p[0] for p in params]
            if param_list not in param_lists:
                param_lists.append(param_list)                
        self.attribute_models_["param_sets"] = param_sets
        self.attribute_models_["param_lists"] = param_lists

        return self

    def predict(self, X):
        """ Checks new data against the normal model.
        Parameters
        ----------
        X: DataFrame, shape (n_samples, n_features).
        Features are characteristics of the requests.
        New data to check.
        """
        result = []
        #Temporary list to feed the final DataFrame (Performance)
        uri_length_lst = []
        try:
            norm_model = self.attribute_models_["uri_length"]
        except AttributeError:
            logging.warning('RequestAnomalyDetector: call to preditct() without previous fit()')
            return None

        #Checking URI length
        for index, row in X.iterrows():
            # TODO: Check more anomaly models
            if len(row.request_url) > norm_model[0] + 2*norm_model[1]:
                uri_length_lst.append(1)
            else:
                uri_length_lst.append(0)

        anomalous = pd.DataFrame(index=X.index, data=uri_length_lst, columns=["uri_length"])
        result.append(anomalous.copy())

        #Checking character distribution
        char_dist_lst = []
        icd = self.attribute_models_["icd"]
        for index, row in X.iterrows():
            char_freq = []
            if len(row.request_url) == 0:
                char_dist_lst.append(0.0)
                continue
            for i in range(256):
                char_count = row.request_url.count(self.all_ascii[i])
                char_freq.append(char_count)
            char_freq.sort(reverse=True)
            ccd = [char_freq[0]]
            ccd.append(sum(char_freq[1:4]))
            ccd.append(sum(char_freq[4:7]))
            ccd.append(sum(char_freq[7:12]))
            ccd.append(sum(char_freq[12:16]))
            ccd.append(sum(char_freq[16:256]))

            #Computing x^2 value
            x2_value = chisquare(ccd, [icd[i]*len(row.request_url) for i in (0,1,2,3,4,5)])
            char_dist_lst.append(x2_value.pvalue)
        anomalous = pd.DataFrame(index=X.index, data=char_dist_lst, columns=["pvalue"])
        result.append(anomalous.copy())

        #Checking sets and lists of parameters
        param_sets_lst = []
        param_lists_lst = []
        for index, row in X.iterrows():
            params = urlparse.parse_qs(urlparse.urlsplit(row.request_url).query)
            detected = 0
            if len(params) > 0:
                keys_set = set(params.keys())
                if keys_set not in self.attribute_models_["param_sets"]:
                    detected = 1
            param_sets_lst.append(detected)

            params = urlparse.parse_qsl(urlparse.urlsplit(row.request_url).query)
            detected = 0
            if len(params) > 0:
                param_list = [p[0] for p in params]
                if param_list not in self.attribute_models_["param_lists"]:
                    detected = 1
            param_lists_lst.append(detected)

        anomalous = pd.DataFrame(index=X.index, data=param_sets_lst,
                                 columns=["param_sets"])
        result.append(anomalous.copy())

        anomalous = pd.DataFrame(index=X.index, data=param_sets_lst,
                                 columns=["param_lists"])
        result.append(anomalous.copy())

        result_df = pd.concat(result, axis=1)
        self.attribute_models_["predict_results"] = result_df

        return result_df

    def kmeans(self):
        kmeans = KMeans(n_clusters=2)
        X = self.attribute_models_["predict_results"]
        kmeans.fit(X)

        self.kmeans_labels = kmeans.predict(X)

        return self.kmeans_labels
