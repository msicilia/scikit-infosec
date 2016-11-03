from skinfosec.datasets import darpa_intrusion

import logging
from timeit import default_timer as timer

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

data = darpa_intrusion.fetch_darpa_intrusion(subset='sample_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_4hour_1998')

#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w1_mon_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w1_tue_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w1_wed_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w1_thu_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w1_fri_1998')

#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w2_mon_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w2_tue_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w2_wed_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w2_thu_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w2_fri_1998')

#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w3_mon_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w2_tue_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w2_wed_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w2_thu_1998')
#data = darpa_intrusion.fetch_darpa_intrusion(subset='train_w2_fri_1998')

#data = darpa_intrusion.fetch_darpa_intrusion(subset='test_w1_mon_1998')


X = data[0]
Y = data[1]
print X.info()
#print Y.axes
X1 = X[['ip_checksum_status','ip_flags_df','ip_flags_mf','ip_frag_offset',
'ip_hdr_len','ip_len','ip_ttl','tcp_ack','tcp_dstport','tcp_srcport']]

print X1

'''

tcp_flags
tcp_flags_ack
tcp_flags_cwr
tcp_flags_ecn
tcp_flags_fin
tcp_flags_ns
tcp_flags_push
tcp_flags_res
tcp_flags_reset
tcp_flags_str
tcp_flags_syn
tcp_flags_urg
tcp_hdr_len
tcp_len
tcp_nxtseq
tcp_option_kind
tcp_option_len
tcp_options
tcp_options_mss
tcp_options_mss_val
tcp_port
tcp_segment_data
tcp_seq

tcp_stream
tcp_urgent_pointer
tcp_window_size
tcp_window_size_scalefactor
tcp_window_size_value
'''
from sklearn.cluster import KMeans
kmeans_model = KMeans(n_clusters=5, random_state=1)
kmeans_model.fit(X1)

labels = kmeans_model.labels_
print labels
