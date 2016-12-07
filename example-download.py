import logging
from sklearn.cluster import KMeans
from skinfosec.datasets import darpa_intrusion


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

'''
Possible subsets

'sample_1998'
'train_4hour_1998'

'train_w1_mon_1998', 'train_w1_tue_1998', 'train_w1_wed_1998',
'train_w1_thu_1998', 'train_w1_fri_1998', 'train_w2_mon_1998',
'train_w2_tue_1998', 'train_w2_wed_1998', 'train_w2_thu_1998',
'train_w2_fri_1998'

'train_w3_mon_1998', 'train_w3_tue_1998', 'train_w3_wed_1998',
'train_w3_thu_1998', 'train_w3_fri_1998', 'train_w4_tue_1998',
'train_w4_wed_1998', 'train_w4_thu_1998', 'train_w4_fri_1998',
'train_w5_mon_1998', 'train_w5_tue_1998', 'train_w5_wed_1998',
'train_w5_thu_1998', 'train_w5_fri_1998', 'train_w6_mon_1998',
'train_w6_tue_1998', 'train_w6_wed_1998', 'train_w6_thu_1998',
'train_w6_fri_1998', 'train_w7_mon_1998', 'train_w7_tue_1998',
'train_w7_wed_1998', 'train_w7_thu_1998', 'train_w7_fri_1998']

'test_w1_mon_1998', 'test_w1_tue_1998', 'test_w1_wed_1998',
'test_w1_thu_1998', 'test_w1_fri_1998', 'test_w2_mon_1998',
'test_w2_tue_1998', 'test_w2_wed_1998', 'test_w2_thu_1998',
'test_w2_fri_1998']
'''

data = darpa_intrusion.fetch_darpa_intrusion(subset='train_4hour_1998')

X = data[0]

X1 = X[['ip_checksum_status', 'ip_flags_df', 'ip_flags_mf', 'ip_frag_offset',
'ip_hdr_len', 'ip_len', 'ip_ttl', 'tcp_ack', 'tcp_dstport', 'tcp_srcport']]

kmeans_model = KMeans(n_clusters=5, random_state=1)
kmeans_model.fit(X1)

data2 = darpa_intrusion.fetch_darpa_intrusion(subset='sample_1998')
X2 = data2[0]
X3 = X2[['ip_checksum_status', 'ip_flags_df', 'ip_flags_mf', 'ip_frag_offset',
'ip_hdr_len', 'ip_len', 'ip_ttl', 'tcp_ack', 'tcp_dstport', 'tcp_srcport']]

labels = kmeans_model.predict(X3)

print(labels)
