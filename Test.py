__author__ = 'Vincenzo Deriu'

from sketch import Sketch
from db_extraction import *

SKETCH_DELTA = 10 ** -9
SKETCH_EPSILON = 0.010181
SKETCH_WINDOW = 10000

db = DBextraction()

# domain_total_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_host_total(domain_total_downloads, SKETCH_WINDOW)
# db.get_host_total(domain_total_downloads)

# domain_malware_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_host_malware(domain_malware_downloads, SKETCH_WINDOW)
# db.get_host_malware(domain_malware_downloads)
#
# domain_suspicious_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_host_suspicious(domain_suspicious_downloads, SKETCH_WINDOW)
# db.get_host_suspicious(domain_suspicious_downloads)
#
# domain_benign_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_host_benign(domain_benign_downloads, SKETCH_WINDOW)
# db.get_host_benign(domain_benign_downloads)
#
# domain_malware_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_host_malware_ratio(domain_malware_ratio)
# db.get_host_malware_ratio(domain_malware_ratio)

# domain_suspicious_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_host_suspicious_ratio(domain_suspicious_ratio)
# db.get_host_suspicious_ratio(domain_suspicious_ratio)
#
# domain_benign_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_host_benign_ratio(domain_benign_ratio)
# db.get_host_benign_ratio(domain_benign_ratio)
#
# domain_avg_av_labels = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
# domain_avg_trusted_labels = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new_av, s_new_trust = db.insert_host_avg_av_labels_trusted_labels(domain_avg_av_labels, domain_avg_trusted_labels, SKETCH_WINDOW)
# db.get_host_avg_av_labels_trusted_labels(domain_avg_av_labels, domain_avg_trusted_labels)
#
# domain_unknown_hashes = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_host_unknown_hashes(domain_unknown_hashes, SKETCH_WINDOW)
# db.get_host_unknown_hashes(domain_unknown_hashes)
#
# domain_total_hashes = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_host_total_hashes(domain_total_hashes, SKETCH_WINDOW)
# db.get_host_total_hashes(domain_total_hashes)

# #
# domain_unknown_hash_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_host_unknown_hash_ratio(domain_unknown_hash_ratio)
# db.get_host_unknown_hash_ratio(domain_unknown_hash_ratio)

server_total_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)

s_new = db.insert_server_total(server_total_downloads, SKETCH_WINDOW)
db.get_server_total(server_total_downloads)
#
# server_malware_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_server_malware(server_malware_downloads, SKETCH_WINDOW)
# db.get_server_malware(server_malware_downloads)
#
# server_suspicious_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_server_suspicious(server_suspicious_downloads, SKETCH_WINDOW)
# db.get_server_suspicious(server_suspicious_downloads)
#
# server_benign_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_server_benign(server_benign_downloads, SKETCH_WINDOW)
# db.get_server_benign(server_benign_downloads)
#
# server_malware_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_server_malware_ratio(server_malware_ratio)
# db.get_server_malware_ratio(server_malware_ratio)
#
# server_suspicious_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_server_suspicious_ratio(server_suspicious_ratio)
# db.get_server_suspicious_ratio(server_suspicious_ratio)
#
# server_benign_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)

# s_new = db.insert_server_benign_ratio(server_benign_ratio, )
# db.get_server_benign_ratio(server_benign_ratio)
#
# server_avg_av_labels = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
# server_avg_trusted_labels = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new_av, s_new_trust = db.insert_server_avg_av_labels_trusted_labels(server_avg_av_labels, server_avg_trusted_labels, SKETCH_WINDOW)
# db.get_server_avg_av_labels_trusted_labels(server_avg_av_labels, server_avg_trusted_labels)
#
# server_unknown_hashes = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_server_unknown_hashes(server_unknown_hashes, SKETCH_WINDOW)
# db.get_server_unknown_hashes(server_unknown_hashes)
#
# server_total_hashes = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_server_total_hashes(server_total_hashes, SKETCH_WINDOW)
# db.get_server_total_hashes(server_total_hashes)
# #
# server_unknown_hash_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_server_unknown_hash_ratio(server_unknown_hash_ratio)
# db.get_server_unknown_hash_ratio(server_unknown_hash_ratio)
#
# bgp_total_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
# s_new = db.insert_bgp_total(bgp_total_downloads, SKETCH_WINDOW)
# db.get_bgp_total(bgp_total_downloads)
#
# bgp_malware_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
# s_new = db.insert_bgp_malware(bgp_malware_downloads, SKETCH_WINDOW)
# db.get_bgp_malware(bgp_malware_downloads)

# bgp_suspicious_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
# s_new = db.insert_bgp_suspicious(bgp_suspicious_downloads, SKETCH_WINDOW)
# db.get_bgp_suspicious(bgp_suspicious_downloads)
#
# bgp_benign_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
# s_new = db.insert_bgp_benign(bgp_benign_downloads, SKETCH_WINDOW)
# db.get_bgp_benign(bgp_benign_downloads)

# bgp_malware_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_bgp_malware_ratio(bgp_malware_ratio)
# db.get_bgp_malware_ratio(bgp_malware_ratio)

# bgp_suspicious_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_bgp_suspicious_ratio(bgp_suspicious_ratio)
# db.get_bgp_suspicious_ratio(bgp_suspicious_ratio)

# bgp_benign_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_bgp_benign_ratio(bgp_benign_ratio)
# db.get_bgp_benign_ratio(bgp_benign_ratio)
#
# bgp_avg_av_labels = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
# bgp_avg_trusted_labels = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new_av, s_new_trust = db.insert_bgp_avg_av_labels_trusted_labels(bgp_avg_av_labels, bgp_avg_trusted_labels, SKETCH_WINDOW)
# db.get_bgp_avg_av_labels_trusted_labels(bgp_avg_av_labels, bgp_avg_trusted_labels)
#
# bgp_unknown_hashes = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_bgp_unknown_hashes(bgp_unknown_hashes, SKETCH_WINDOW)
# db.get_bgp_unknown_hashes(bgp_unknown_hashes)
#
# bgp_total_hashes = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_bgp_total_hashes(bgp_total_hashes, SKETCH_WINDOW)
# db.get_bgp_total_hashes(bgp_total_hashes)
#
# bgp_unknown_hash_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_bgp_unknown_hash_ratio(bgp_unknown_hash_ratio)
# db.get_bgp_unknown_hash_ratio(bgp_unknown_hash_ratio)

#twold_mapping, twold_list = db.get_twold_mapping_from_sketch(SKETCH_WINDOW)

#
#
# twold_total_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
# s_new = db.insert_twold_total(twold_total_downloads, SKETCH_WINDOW)
# db.get_twold_total(twold_total_downloads)
#
# twold_malware_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
# s_new = db.insert_twold_malware(twold_malware_downloads, SKETCH_WINDOW)
# db.get_twold_malware(twold_malware_downloads)
#
# twold_suspicious_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
# s_new = db.insert_twold_suspicious(twold_suspicious_downloads, SKETCH_WINDOW)
# db.get_twold_suspicious(twold_suspicious_downloads)
#
# twold_benign_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
# s_new = db.insert_twold_benign(twold_benign_downloads, SKETCH_WINDOW)
# db.get_twold_benign(twold_benign_downloads)
#
# twold_malware_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_twold_malware_ratio(twold_malware_ratio)
# db.get_twold_malware_ratio(twold_malware_ratio)
#
# twold_suspicious_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_twold_suspicious_ratio(twold_suspicious_ratio)
# db.get_twold_suspicious_ratio(twold_suspicious_ratio)
#
# twold_benign_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_twold_benign_ratio(twold_benign_ratio)
# db.get_twold_benign_ratio(twold_benign_ratio)
#
# twold_avg_av_labels = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
# twold_avg_trusted_labels = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new_av, s_new_trust =db.insert_twold_avg_av_labels_trusted_labels(twold_avg_av_labels, twold_avg_trusted_labels, SKETCH_WINDOW)
# db.get_twold_avg_av_labels_trusted_labels(twold_avg_av_labels, twold_avg_trusted_labels)
#
# twold_unknown_hashes = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_twold_unknown_hashes(twold_unknown_hashes, SKETCH_WINDOW)
# db.get_twold_unknown_hashes(twold_unknown_hashes)
#
# twold_total_hashes = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_twold_total_hashes(twold_total_hashes, SKETCH_WINDOW)
# db.get_twold_total_hashes(twold_total_hashes)
#
# twold_unknown_hash_ratio = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_twold_unknown_hash_ratio(twold_unknown_hash_ratio)
# db.get_twold_unknown_hash_ratio(twold_unknown_hash_ratio)
#
# hash_life_time = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
# num_dumps_same_hash = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new_hl, s_new_md = db.insert_hash_life_time_min_dumps_same_hash(hash_life_time, num_dumps_same_hash, SKETCH_WINDOW)
# db.get_hash_life_time_min_dumps_same_hash(hash_life_time, num_dumps_same_hash)

#hash_daily_dump_rate = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)

# s_new = db.insert_hash_daily_dump_rate(hash_daily_dump_rate, SKETCH_WINDOW)
# db.get_hash_daily_dump_rate(hash_daily_dump_rate)
#
# estimated_client_same_hash = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 1)
#
# s_new = db.insert_estimated_clients_same_hash(estimated_client_same_hash, SKETCH_WINDOW)
# db.get_estimated_clients_with_same_hash(estimated_client_same_hash)
#
# url_malware_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON_URL, SKETCH_WINDOW, 0)
#
# s_new = db.insert_url_malware_downloads(url_malware_downloads, SKETCH_WINDOW)
# db.get_url_malware_downloads(url_malware_downloads)
#
# url_total_downloads = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_url_total_downloads(url_total_downloads, SKETCH_WINDOW)
#db.get_url_total_downloads(url_total_downloads)

# url_distinct_sha1s = Sketch(SKETCH_DELTA, SKETCH_EPSILON, SKETCH_WINDOW, 0)
#
# s_new = db.insert_url_distinct_sha1(url_distinct_sha1s, SKETCH_WINDOW)
# db.get_url_distinct_sha1(url_distinct_sha1s)
#
# url_struct_md = Sketch(SKETCH_DELTA, SKETCH_EPSILON_URL, SKETCH_WINDOW, 0)
# url_struct_td = Sketch(SKETCH_DELTA, SKETCH_EPSILON_URL, SKETCH_WINDOW, 0)
# url_struct_ds = Sketch(SKETCH_DELTA, SKETCH_EPSILON_URL, SKETCH_WINDOW, 0)
#
# s_new_md, s_new_td, s_new_ds = db.insert_url_struct_features(url_struct_md, url_struct_td, url_struct_ds, SKETCH_WINDOW)
# db.get_url_struct_features(url_struct_md, url_struct_td, url_struct_ds)