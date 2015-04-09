__author__ = 'Daniele Ucci'

from epsilonOracle import epsilonOracle
import sys

features = [ "domain_total_downloads", "domain_malware_downloads", "domain_suspicious_downloads",
             "domain_benign_downloads", "domain_malware_ratio", "domain_suspicious_ratio", "domain_benign_ratio",
             "domain_avg_av_labels", "domain_avg_trusted_labels", "domain_unknown_hashes", "domain_total_hashes",
             "domain_unknown_hash_ratio", "server_total_downloads", "server_malware_downloads",
             "server_suspicious_downloads", "server_benign_downloads", "server_malware_ratio",
             "server_suspicious_ratio", "server_benign_ratio", "server_avg_av_labels", "server_avg_trusted_labels",
             "server_unknown_hashes", "server_total_hashes", "server_unknown_hash_ratio", "bgp_total_downloads",
             "bgp_malware_downloads", "bgp_suspicious_downloads", "bgp_benign_downloads", "bgp_malware_ratio",
             "bgp_suspicious_ratio", "bgp_benign_ratio", "bgp_avg_av_labels", "bgp_avg_trusted_labels",
             "bgp_unknown_hashes", "bgp_total_hashes", "bgp_unknown_hash_ratio", "twold_total_downloads",
             "twold_malware_downloads", "twold_suspicious_downloads", "twold_benign_downloads", "twold_malware_ratio",
             "twold_suspicious_ratio", "twold_benign_ratio", "twold_avg_av_labels", "twold_avg_trusted_labels",
             "twold_unknown_hashes", "twold_total_hashes", "twold_unknown_hash_ratio", "hash_life_time",
             "num_dumps_same_hash", "hash_daily_dump_rate_per_client", "estimated_clients_with_same_hash",
             "url_malware_downloads","url_total_downloads", "url_distinct_sha1s", "url_struct_malware_downloads",
             "url_struct_total_downloads", "url_struct_distinct_sha1s"]

max_error_rate = float(sys.argv[1])
feature_id = int(sys.argv[2])

print len(features)

e_oracle = epsilonOracle(max_error_rate)

print "Computing error up to %d relative to feature %d..." % (int(max_error_rate), feature_id)


out_file = open("PUT_PWD_HERE!!" + str(feature_id) + "-"+ features[feature_id] + ".txt","w")
e_oracle.compute_percentage_error(feature_id, out_file)