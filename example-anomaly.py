from skinfosec.models.anomaly.web import RequestAnomalyDetector


# This is using AWS via boto.
# It assumes your AWS credentials are provided in a boto config:
#SEE: http://boto.readthedocs.org/en/latest/boto_config_tut.html

#import boto3
#s3 = boto3.resource('s3')
#for bucket in s3.buckets.all():
#    print(bucket.name)

from pyspark import SparkContext
from pyspark.sql import SQLContext, Row
from odo import odo
from apache_log_parser import make_parser

logFile = "access.log"  # Should be some file on your system
sc = SparkContext("local", "Example Anomaly Dectection")
sql = SQLContext(sc)
logData = sc.textFile(logFile).cache()


parser = make_parser('%h %u %l %t \"%r\" %>s %b')

#logData = logData.map(lambda line: parser(line)["remote_host"])
cols=["remote_host", "remote_user", "remote_logname",
       "time_received_tz_datetimeobj", "request_http_ver", "request_method",
       "request_url", "status", "response_bytes_clf"]

# Note that parser(line) returns a dict. We do the following:
# - Filter out keys in cols, and get a list.
# - Convert each value of the dict into str
# - Join together the resulting str into a single line.
#logData = logData.map(lambda line: ''.join([str(e)+"," for e in [parser(line)[k] for k in cols]]))

def parse(line):
    parsed = parser(line)
    # Requires conversion to str
    filtered = {k:str(v) for k,v in parsed.items() if k in cols}
    return filtered

data = logData.map(lambda line: parse(line))
print data.take(3)


#from blaze import Table
#t = Table(data)
#print t.head(3)
#print type(data)
df = data.toDF()
longitudes = df.select(df["request_url"]).map(lambda r: len(r[0])).mean()
print longitudes
#print avg
#print df.printSchema()



#srdd = odo(logData, sql, dshape='var * {name: string, amount: float64}')


#X = preprocess_requests(content)

ad = RequestAnomalyDetector()
#ad = ad.fit(X)
#anomalies = ad.predict(X)
#print anomalies["uri_length"].head()
