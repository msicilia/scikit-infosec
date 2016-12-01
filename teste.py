import logging
from skinfosec.datasets import chuvakin_httpd

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

X = chuvakin_httpd.fetch_chuvakin_logs()
print X.head()
