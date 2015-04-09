__author__ = 'Daniele Ucci'

import db_extraction
from sketch import Sketch
import math
import shutil
import pickle

features = [ "host_total", "host_malware", "host_suspicious",
             "host_benign", "host_malware_ratio", "host_suspicious_ratio", "host_benign_ratio",
             "host_avg_av_labels", "host_avg_trusted_labels", "host_unknown_hash", "host_total_hash",
             "host_unknown_hash_ratio", "server_total", "server_malware",
             "server_suspicious", "server_benign", "server_malware_ratio",
             "server_suspicious_ratio", "server_benign_ratio", "server_avg_av_labels", "server_avg_trusted_labels",
             "server_unknown_hashes", "server_total_hashes", "server_unknown_hash_ratio", "bgp_total",
             "bgp_malware", "bgp_suspicious", "bgp_benign", "bgp_malware_ratio",
             "bgp_suspicious_ratio", "bgp_benign_ratio", "bgp_avg_av_labels", "bgp_avg_trusted_labels",
             "bgp_unknown_hashes", "bgp_total_hash", "bgp_unknown_hash_ratio", "twold_total",
             "twold_malware", "twold_suspicious", "twold_benign", "twold_malware_ratio",
             "twold_suspicious_ratio", "twold_benign_ratio", "twold_avg_av_labels", "twold_avg_trusted_labels",
             "twold_unknown_hash", "twold_total_hash", "twold_unknown_hash_ratio", "hash_life_time",
             "num_dumps_with_same_hash", "hash_daily_dump_rate", "estimated_clients_same_hash",
             "url_malware","url_total", "url_distinct_sha1s", "url_struct_malware_downloads",
             "url_struct_total_downloads", "url_struct_distinct_sha1s"]

SKETCH_DELTA = 10**-9
DEFAULT_SKETCH_EPSILON = 0.0001
SKETCH_WINDOW = 10000


class epsilonOracle:

    db = db_extraction.DBextraction()
    max_error_rate = 0.0
    min_error_rate = 0.0

    def __init__(self, max_error_rate):
        self.max_error_rate = max_error_rate

    def get_stats(self, feature_id, sketch):
        if(feature_id == 0):
            self.db.insert_host_total(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 1):
            self.db.insert_host_malware(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 2):
            self.db.insert_host_suspicious(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 3):
            self.db.insert_host_benign(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 4):
            # Data structures of interest for computing error
            get_host_total(self.db, SKETCH_WINDOW)
            get_host_malware(self.db, SKETCH_WINDOW)

            self.db.insert_host_malware_ratio(sketch)
            self.db.domain_total_downloads = {}
            self.db.domain_malware_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 5):
            get_host_total(self.db, SKETCH_WINDOW)
            get_host_suspicious(self.db, SKETCH_WINDOW)

            self.db.insert_host_suspicious_ratio(sketch)
            self.db.domain_total_downloads = {}
            self.db.domain_suspicious_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 6):
            get_host_total(self.db, SKETCH_WINDOW)
            get_host_benign(self.db, SKETCH_WINDOW)

            self.db.insert_host_benign_ratio(sketch)
            self.db.domain_total_downloads = {}
            self.db.domain_benign_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 7):
            self.db.insert_host_avg_av_labels(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 8):
            self.db.insert_host_avg_trusted_labels(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 9):
            self.db.insert_host_unknown_hashes(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 10):
            self.db.insert_host_total_hashes(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 11):
            get_host_total_hashes(self.db, SKETCH_WINDOW)
            get_host_unknown_hashes(self.db, SKETCH_WINDOW)

            self.db.insert_host_unknown_hash_ratio(sketch)
            self.db.domain_total_hash = {}
            self.db.domain_unknown_hash = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 12):
            self.db.insert_server_total(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 13):
            self.db.insert_server_malware(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 14):
            self.db.insert_server_suspicious(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 15):
            self.db.insert_server_benign(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 16):
            # Data structures of interest for computing error
            get_server_total(self.db, SKETCH_WINDOW)
            get_server_malware(self.db, SKETCH_WINDOW)

            self.db.insert_server_malware_ratio(sketch)
            self.db.server_total_downloads = {}
            self.db.server_malware_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 17):
            get_server_total(self.db, SKETCH_WINDOW)
            get_server_suspicious(self.db, SKETCH_WINDOW)

            self.db.insert_server_suspicious_ratio(sketch)
            self.db.server_total_downloads = {}
            self.db.server_suspicious_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 18):
            get_server_total(self.db, SKETCH_WINDOW)
            get_server_benign(self.db, SKETCH_WINDOW)

            self.db.insert_server_benign_ratio(sketch)
            self.db.server_total_downloads = {}
            self.db.server_benign_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 19):
            self.db.insert_server_avg_av_labels(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 20):
            self.db.insert_server_avg_trusted_labels(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 21):
            self.db.insert_server_unknown_hashes(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 22):
            self.db.insert_server_total_hashes(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 23):
            get_server_total_hashes(self.db, SKETCH_WINDOW)
            get_server_unknown_hashes(self.db, SKETCH_WINDOW)


            self.db.insert_server_unknown_hash_ratio(sketch)
            self.db.server_total_hash = {}
            self.db.server_unknown_hash = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id >= 24 and feature_id < 36):
            if(not self.db.bgp_list):
                get_bgp_list(self.db, SKETCH_WINDOW)

        if(feature_id == 24):
            self.db.insert_bgp_total(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 25):
            self.db.insert_bgp_malware(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 26):
            self.db.insert_bgp_suspicious(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 27):
            self.db.insert_bgp_benign(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 28):
            # Data structures of interest for computing error
            get_bgp_total(self.db, SKETCH_WINDOW)
            get_bgp_malware(self.db, SKETCH_WINDOW)

            self.db.insert_bgp_malware_ratio(sketch)
            self.db.bgp_total_downloads = {}
            self.db.bgp_malware_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 29):
            get_bgp_total(self.db, SKETCH_WINDOW)
            get_bgp_suspicious(self.db, SKETCH_WINDOW)

            self.db.insert_bgp_suspicious_ratio(sketch)
            self.db.bgp_total_downloads = {}
            self.db.bgp_suspicious_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 30):
            get_bgp_total(self.db, SKETCH_WINDOW)
            get_bgp_benign(self.db, SKETCH_WINDOW)

            self.db.insert_bgp_benign_ratio(sketch)
            self.db.bgp_total_downloads = {}
            self.db.bgp_benign_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 31):
            self.db.insert_bgp_avg_av_labels(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 32):
            self.db.insert_bgp_avg_trusted_labels(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 33):
            self.db.insert_bgp_unknown_hashes(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 34):
            self.db.insert_bgp_total_hashes(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 35):
            get_bgp_total_hashes(self.db, SKETCH_WINDOW)
            get_bgp_unknown_hashes(self.db, SKETCH_WINDOW)


            self.db.insert_bgp_unknown_hash_ratio(sketch)
            self.db.bgp_total_hash = {}
            self.db.bgp_unknown_hash = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id >= 36 and feature_id < 48):
            if(not self.db.host_twold_mapping):
                self.db.get_twold_mapping_from_sketch()

        if(feature_id == 36):
            self.db.insert_twold_total(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 37):
            self.db.insert_twold_malware(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 38):
            self.db.insert_twold_suspicious(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 39):
            self.db.insert_twold_benign(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 40):
            # Data structures of interest for computing error
            get_twold_total(self.db, SKETCH_WINDOW)
            get_twold_malware(self.db, SKETCH_WINDOW)

            self.db.insert_twold_malware_ratio(sketch)
            self.db.twoldp_total_downloads = {}
            self.db.twold_malware_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 41):
            get_twold_total(self.db, SKETCH_WINDOW)
            get_twold_suspicious(self.db, SKETCH_WINDOW)

            self.db.insert_twold_suspicious_ratio(sketch)
            self.db.twold_total_downloads = {}
            self.db.twold_suspicious_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 42):
            get_twold_total(self.db, SKETCH_WINDOW)
            get_twold_benign(self.db, SKETCH_WINDOW)

            self.db.insert_twold_benign_ratio(sketch)
            self.db.twold_total_downloads = {}
            self.db.twold_benign_downloads = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 43):
            self.db.insert_twold_avg_av_labels(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 44):
            self.db.insert_twold_avg_trusted_labels(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 45):
            self.db.insert_twold_unknown_hashes(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 46):
            self.db.insert_twold_total_hashes(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 47):
            get_twold_total_hashes(self.db, SKETCH_WINDOW)
            get_twold_unknown_hashes(self.db, SKETCH_WINDOW)

            self.db.insert_twold_unknown_hash_ratio(sketch)
            self.db.twold_total_hash = {}
            self.db.twold_unknown_hash = {}
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 48):
            self.db.insert_hash_life_time(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 49):
            self.db.insert_min_dumps_same_hash (sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 50):
            self.db.insert_hash_daily_dump_rate(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 51):
            self.db.insert_estimated_clients_same_hash(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 52):
            self.db.insert_url_malware_downloads(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 53):
            self.db.insert_url_total_downloads(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 54):
            self.db.insert_url_distinct_sha1(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 55):
            self.db.insert_url_struct_malware(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 56):
            self.db.insert_url_struct_total (sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)
        if(feature_id == 57):
            self.db.insert_url_struct_distinct_sha1(sketch, SKETCH_WINDOW)
            return get_percentage_error(self.db, feature_id, sketch)

    def create_sketch(self, feature_id, epsilon):
        if(feature_id == 0):
            print "EPSILON_ORACLE:: Computing error for 'domain_total_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 1):
            print "EPSILON_ORACLE:: Computing error for 'domain_malware_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 2):
            print "EPSILON_ORACLE:: Computing error for 'domain_suspicious_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 3):
            print "EPSILON_ORACLE:: Computing error for 'domain_benign_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 4):
            print "EPSILON_ORACLE:: Computing error for 'domain_malware_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 5):
            print "EPSILON_ORACLE:: Computing error for 'domain_suspicious_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 6):
            print "EPSILON_ORACLE:: Computing error for 'domain_benign_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 7):
            print "EPSILON_ORACLE:: Computing error for 'domain_avg_av_labels'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 8):
            print "EPSILON_ORACLE:: Computing error for 'domain_avg_trusted_labels'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 9):
            print "EPSILON_ORACLE:: Computing error for 'domain_unknown_hashes'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 10):
            print "EPSILON_ORACLE:: Computing error for 'domain_total_hashes'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 11):
            print "EPSILON_ORACLE:: Computing error for 'domain_unknown_hash_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 12):
            print "EPSILON_ORACLE:: Computing error for 'server_total_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 13):
            print "EPSILON_ORACLE:: Computing error for 'server_malware_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 14):
            print "EPSILON_ORACLE:: Computing error for 'server_suspicious_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 15):
            print "EPSILON_ORACLE:: Computing error for 'server_benign_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 16):
            print "EPSILON_ORACLE:: Computing error for 'server_malware_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 17):
            print "EPSILON_ORACLE:: Computing error for 'server_suspicious_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 18):
            print "EPSILON_ORACLE:: Computing error for 'server_benign_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 19):
            print "EPSILON_ORACLE:: Computing error for 'server_avg_av_labels'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 20):
            print "EPSILON_ORACLE:: Computing error for 'server_avg_trusted_labels'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 21):
            print "EPSILON_ORACLE:: Computing error for 'server_unknown_hashes'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 22):
            print "EPSILON_ORACLE:: Computing error for 'server_total_hashes'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 23):
            print "EPSILON_ORACLE:: Computing error for 'domain_unknown_hash_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 24):
            print "EPSILON_ORACLE:: Computing error for 'bgp_total_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 25):
            print "EPSILON_ORACLE:: Computing error for 'bgp_malware_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 26):
            print "EPSILON_ORACLE:: Computing error for 'bgp_suspicious_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 27):
            print "EPSILON_ORACLE:: Computing error for 'bgp_benign_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 28):
            print "EPSILON_ORACLE:: Computing error for 'bgp_malware_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 29):
            print "EPSILON_ORACLE:: Computing error for 'bgp_suspicious_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 30):
            print "EPSILON_ORACLE:: Computing error for 'bgp_benign_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 31):
            print "EPSILON_ORACLE:: Computing error for 'bgp_avg_av_labels'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 32):
            print "EPSILON_ORACLE:: Computing error for 'bgp_avg_trusted_labels'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 33):
            print "EPSILON_ORACLE:: Computing error for 'bgp_unknown_hashes'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 34):
            print "EPSILON_ORACLE:: Computing error for 'bgp_total_hashes'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 35):
            print "EPSILON_ORACLE:: Computing error for 'bgp_unknown_hash_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 36):
            print "EPSILON_ORACLE:: Computing error for 'twold_total_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 37):
            print "EPSILON_ORACLE:: Computing error for 'twold_malware_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 38):
            print "EPSILON_ORACLE:: Computing error for 'twold_suspicious_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 39):
            print "EPSILON_ORACLE:: Computing error for 'twold_benign_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 40):
            print "EPSILON_ORACLE:: Computing error for 'twold_malware_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 41):
            print "EPSILON_ORACLE:: Computing error for 'twold_suspicious_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 42):
            print "EPSILON_ORACLE:: Computing error for 'twold_benign_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 43):
            print "EPSILON_ORACLE:: Computing error for 'twold_avg_av_labels'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 44):
            print "EPSILON_ORACLE:: Computing error for 'twold_avg_trusted_labels'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 45):
            print "EPSILON_ORACLE:: Computing error for 'twold_unknown_hashes'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 46):
            print "EPSILON_ORACLE:: Computing error for 'twold_total_hashes'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 47):
            print "EPSILON_ORACLE:: Computing error for 'twold_unknown_hash_ratio'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 48):
            print "EPSILON_ORACLE:: Computing error for 'hash_life_time'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 49):
            print "EPSILON_ORACLE:: Computing error for 'num_dumps_same_hash'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 50):
            print "EPSILON_ORACLE:: Computing error for 'hash_daily_dump_rate'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 51):
            print "EPSILON_ORACLE:: Computing error for 'estimated_client_with_same_hash'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 1)

        elif(feature_id == 52):
            print "EPSILON_ORACLE:: Computing error for 'url_malware_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 53):
            print "EPSILON_ORACLE:: Computing error for 'url_total_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 54):
            print "EPSILON_ORACLE:: Computing error for 'url_distinct_sha1'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 55):
            print "EPSILON_ORACLE:: Computing error for 'url_struct_malware_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 56):
            print "EPSILON_ORACLE:: Computing error for 'url_struct_total_downloads'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

        elif(feature_id == 57):
            print "EPSILON_ORACLE:: Computing error for 'url_struct_distinct_sha1'..."
            return Sketch(SKETCH_DELTA, epsilon, SKETCH_WINDOW, 0)

    def compute_percentage_error(self, feature_id, out_file):
        w = 3
        epsilon = math.exp(1)/w
        error_rate = 100

        max_error_rate = int(self.max_error_rate + 1)

        percentages_map = {}

        print epsilon

        for key in range(max_error_rate):
            percentages_map[key] = 0

        while error_rate > 0 and epsilon > 0.0001:
            sketch = self.create_sketch(feature_id, epsilon)
            error_rate = self.get_stats(feature_id, sketch)

            print error_rate

            if int(error_rate) in range(max_error_rate):
                percentages_map[int(error_rate)] = epsilon

            w += 1
            epsilon = math.exp(1)/w


        for key, value in percentages_map.iteritems():
            if(value is not 0 and key <= 10):
                sketch = self.create_sketch(feature_id, value)
                error_rate = self.get_stats(feature_id, sketch)
                self.create_serialized(key, value, feature_id)
                out_file.write("Error rate computed: %f \t epsilon: %f\n" % (error_rate, value))
            elif(value is 0 and key <= 10):
                # put the first sketch which is smaller
                self.create_serialized(key, value, feature_id)
                out_file.write("Error rate computed: %f \t epsilon: %f\n" % (key, value))
            elif(value is not 0 and key > 10):
                out_file.write("Error rate computed: %f \t epsilon: %f\n" % (error_rate, value))
            else:
                out_file.write("Error rate computed: %f \t epsilon: %f\n" % (key, value))




    def compute_percentage_error2(self, feature_id, out_file):
        epsilon = DEFAULT_SKETCH_EPSILON
        sketch = self.create_sketch(feature_id, epsilon)
        error_rate = self.get_stats(feature_id, sketch)
        last_error_rate = -1.0
        inc_rate = 1.0

        print error_rate
        while error_rate < self.max_error_rate:
            if(int(epsilon) == 1):
                break
            while not (error_rate >= self.min_error_rate and error_rate < self.min_error_rate + 1):
                print ("Error rate: %f - epsilon: %f" % (error_rate, epsilon))
                if(error_rate > self.min_error_rate + 1):
                    #TODO: temporary patch
                    if(error_rate >= self.max_error_rate):
                        break
                    out_file.write("Error rate computed: %f \t epsilon: %f\n" % (error_rate, epsilon))
                    self.create_serialized(error_rate, epsilon, feature_id)
                    sketch.print_stats(sketch.get_type(), out_file)
                    self.min_error_rate += 1.0
                    continue
                # print "Error rate computed: %f" % error_rate
                epsilon += 0.0001 * inc_rate
                if(int(epsilon) == 1):
                    out_file.write("Error given in input not reached... Exiting\n")
                    break
                sketch = self.create_sketch(feature_id, epsilon)
                error_rate = self.get_stats(feature_id, sketch)
                if(last_error_rate == error_rate):
                    inc_rate += 2
                else:
                    inc_rate = 1.0
                last_error_rate = error_rate
            self.min_error_rate += 1.0
            # print("Error rate computed: %f \t epsilon: %f" % (error_rate, epsilon))
            out_file.write("Error rate computed: %f \t epsilon: %f \t " % (error_rate, epsilon))
            self.create_serialized(error_rate, epsilon, feature_id)
            sketch.print_stats(sketch.get_type(), out_file)

        return

    def create_serialized(self, error_rate, epsilon, feature_id):
        shutil.copy("./serialized/%s.p" % features[feature_id], "./serialized/%s/%s-%d.p" % (error_rate,features[feature_id], error_rate) )

        return

# TWOLD


def get_twold_total(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    for twold in db.twold_list:

        cursor.execute("""
            SELECT COUNT(DISTINCT dump_id)
            FROM pe_dumps AS pe
            WHERE pe.host LIKE %s AND
                pe.dump_id > %s""",
                             (twold, start_id))

        twold_total_downloads = cursor.fetchone()[0]
        db.twold_total_downloads[twold] = twold_total_downloads


def get_twold_malware(db, window):

    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    for twold in db.twold_list:
        cursor.execute("""SELECT COUNT(DISTINCT dump_id)
                    FROM pe_dumps AS pe JOIN
                        ped_vts_mapping AS pvm USING (dump_id),
                        virus_total_scans AS vts
                    WHERE vts.trusted_av_labels > 1 AND
                        pe.host LIKE %s AND
                        pe.dump_id > %s AND
                        vts.vt_id = pvm.vt_id""",
                                 (twold, start_id))

        twold_malware_downloads = cursor.fetchone()[0]
        db.twold_malware_downloads[twold] = twold_malware_downloads


def get_twold_suspicious(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    for twold in db.twold_list:
        cursor.execute("""SELECT COUNT(DISTINCT dump_id)
                    FROM pe_dumps AS pe JOIN
                        ped_vts_mapping AS pvm USING (dump_id),
                        virus_total_scans AS vts
                    WHERE vts.num_av_labels > 1 AND
                        pe.host LIKE %s AND
                        pe.dump_id > %s AND
                        vts.vt_id = pvm.vt_id""",
                                 (twold, start_id))

        twold_suspicious_downloads = cursor.fetchone()[0]
        db.twold_suspicious_downloads[twold] = twold_suspicious_downloads


def get_twold_benign(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    for twold in db.twold_list:
            cursor.execute("""SELECT COUNT(DISTINCT dump_id)
                    FROM pe_dumps AS pe JOIN
                        ped_vts_mapping AS pvm USING (dump_id),
                        virus_total_scans AS vts
                    WHERE vts.num_av_labels = 0 AND
                        pe.host LIKE %s AND
                        pe.dump_id > %s AND
                        vts.vt_id = pvm.vt_id""",
                                 (twold, start_id))

            twold_benign_downloads = cursor.fetchone()[0]
            db.twold_benign_downloads[twold] = twold_benign_downloads


def get_twold_total_hashes(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    for twold in db.twold_list:
        cursor.execute("""
                SELECT COUNT(DISTINCT pe.sha1)
                FROM pe_dumps AS pe
                WHERE pe.host LIKE %s AND
                    pe.corrupt = 'f' AND
                    pe.dump_id > %s """,
                                 (twold, start_id))
        twold_total_hashes = cursor.fetchone()[0]
        db.twold_total_hash[twold] = twold_total_hashes


def get_twold_unknown_hashes(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    for twold in db.twold_list:
        cursor.execute("""SELECT COUNT(DISTINCT b.sha1)
                FROM
                    (SELECT pe.sha1, MIN(dump_id) AS min_id
                    FROM pe_dumps AS pe
                    WHERE pe.host LIKE %s AND
                        pe.dump_id > %s AND
                        pe.corrupt = 'f' GROUP BY pe.sha1) as a
                    JOIN
                    (SELECT p.sha1, num_av_labels, trusted_av_labels, dump_id
                    FROM pe_dumps AS p JOIN
                        ped_vts_mapping as pvm USING (dump_id),
                        virus_total_scans as vts
                    WHERE pvm.vt_id = vts.vt_id AND
                        p.host LIKE %s AND
                        dump_id > %s AND
                        p.corrupt='f') as b
                    ON a.min_id = b.dump_id
                WHERE num_av_labels IS NULL""",
                                 (twold, start_id, twold, start_id))
        twold_unknown_hashes = cursor.fetchone()[0]
        db.twold_unknown_hash[twold] = twold_unknown_hashes

# BGP


def get_bgp_total(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    for bgp in db.bgp_list:
        cursor.execute("""
                SELECT COUNT(DISTINCT dump_id)
                FROM pe_dumps AS pe
                WHERE pe.server << %s AND
                    pe.dump_id > %s""",
                                 (bgp, start_id))
        bgp_total_downloads = cursor.fetchone()[0]
        db.bgp_total_downloads[bgp] = bgp_total_downloads


def get_bgp_malware(db, window):

    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    for bgp in db.bgp_list:
        cursor.execute("""SELECT COUNT(DISTINCT dump_id)
            FROM pe_dumps AS pe JOIN
                ped_vts_mapping AS pvm USING (dump_id),
                virus_total_scans AS vts
            WHERE vts.trusted_av_labels > 1 AND
                pe.server << %s AND
                pe.dump_id > %s AND
                vts.vt_id = pvm.vt_id""",
                             (bgp, start_id))
        bgp_malware_downloads = cursor.fetchone()[0]
        db.bgp_malware_downloads[bgp] = bgp_malware_downloads


def get_bgp_suspicious(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    for bgp in db.bgp_list:
        cursor.execute("""SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.num_av_labels > 1 AND
            pe.server << %s AND
            pe.dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
                         (bgp, start_id))
        bgp_suspicious_downloads = cursor.fetchone()[0]
        db.bgp_suspicious_downloads[bgp] = bgp_suspicious_downloads


def get_bgp_benign(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    for bgp in db.bgp_list:
        cursor.execute("""SELECT COUNT(DISTINCT dump_id)
            FROM pe_dumps AS pe JOIN
                    ped_vts_mapping AS pvm USING (dump_id),
                    virus_total_scans AS vts
            WHERE vts.num_av_labels = 0 AND
                pe.server << %s AND
                pe.dump_id > %s AND
                vts.vt_id = pvm.vt_id""",
                                 (bgp, start_id))
        bgp_benign_downloads = cursor.fetchone()[0]
        db.bgp_benign_downloads[bgp] = bgp_benign_downloads


def get_bgp_total_hashes(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window


    for bgp in db.bgp_list:
        cursor.execute("""
            SELECT COUNT(DISTINCT pe.sha1)
            FROM pe_dumps AS pe
            WHERE pe.server << %s AND
                pe.corrupt = 'f' AND
                pe.dump_id > %s """,
                             (bgp, start_id))
        bgp_total_hashes = cursor.fetchone()[0]
        db.bgp_total_hash[bgp] = bgp_total_hashes


def get_bgp_unknown_hashes(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    for bgp in db.bgp_list:
        cursor.execute("""SELECT COUNT(DISTINCT b.sha1)
            FROM
                (SELECT pe.sha1, MIN(dump_id) AS min_id
                FROM pe_dumps AS pe
                WHERE pe.server << %s AND
                    pe.dump_id > %s AND
                    pe.corrupt = 'f' GROUP BY pe.sha1) as a
                JOIN
                (SELECT p.sha1, num_av_labels, trusted_av_labels, dump_id
                FROM pe_dumps AS p JOIN
                    ped_vts_mapping as pvm USING (dump_id),
                    virus_total_scans as vts
                WHERE pvm.vt_id = vts.vt_id AND
                    p.server << %s AND
                    dump_id > %s AND
                    p.corrupt='f') as b
                ON a.min_id = b.dump_id
            WHERE num_av_labels IS NULL""",
                             (bgp, start_id, bgp, start_id))
        bgp_unknown_hashes = cursor.fetchone()[0]
        db.bgp_unknown_hash[bgp] = bgp_unknown_hashes


# SERVER

def get_server_total(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT server,count(server)
            FROM pe_dumps AS pe
            WHERE
                pe.dump_id > %d and server is not null
            GROUP BY server""" %
                    (start_id,))
    for row in cursor:
        if row is not None:
            db.server_total_downloads[row[0]] = row[1]


def get_server_malware(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT server,count(server)
            FROM pe_dumps AS pe JOIN
                 ped_vts_mapping AS pvm USING (dump_id),
                 virus_total_scans AS vts
            WHERE
                pe.dump_id > %d AND
                vts.trusted_av_labels > 1 AND
                vts.vt_id = pvm.vt_id AND
                server is not null
            GROUP BY server""" %
                   (start_id,))

    for row in cursor:
        if row is not None:
            db.server_malware_downloads[row[0]] = row[1]


def get_server_suspicious(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT server,count(server)
            FROM pe_dumps AS pe JOIN
                 ped_vts_mapping AS pvm USING (dump_id),
                 virus_total_scans AS vts
            WHERE
                pe.dump_id > %d AND
                vts.num_av_labels > 1 AND
                vts.vt_id = pvm.vt_id AND
                server is not null
            GROUP BY server""" %
                   (start_id,))

    for row in cursor:
        if row is not None:
            db.server_suspicious_downloads[row[0]] = row[1]


def get_server_benign(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT server, count(server)
            FROM pe_dumps AS pe JOIN
                 ped_vts_mapping AS pvm USING (dump_id),
                 virus_total_scans AS vts
            WHERE
                pe.dump_id > %d AND
                vts.num_av_labels = 0 AND
                vts.vt_id = pvm.vt_id AND
                server is not null
            GROUP BY server""" %
                   (start_id,))

    for row in cursor:
        if row is not None:
            db.server_benign_downloads[row[0]] = row[1]


def get_server_total_hashes(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()
    inner_cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT distinct server
                        FROM pe_dumps
                        WHERE dump_id > %d
                        and server is not null and corrupt = 'f'""" %
                   (start_id,))

    for row in cursor:
        if row is not None:
            server = row[0]
            inner_cursor.execute("""SELECT COUNT(DISTINCT pe.sha1)
                    FROM pe_dumps AS pe
                    WHERE pe.server = '%s' AND
                        pe.corrupt = 'f' AND
                        pe.dump_id > %d """ %
                                 (server, start_id))
            server_total_hashes = inner_cursor.fetchone()[0]
            db.server_total_hash[server] = server_total_hashes


def get_server_unknown_hashes(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()
    inner_cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT distinct server
                        FROM pe_dumps
                        WHERE dump_id > %d
                        and server is not null and corrupt = 'f'""" %
                   (start_id,))

    for row in cursor:
        if row is not None:
            server = row[0]
            inner_cursor.execute("""SELECT COUNT(DISTINCT b.sha1)
                    FROM
                        (SELECT pe.sha1, MIN(dump_id) AS min_id
                        FROM pe_dumps AS pe
                        WHERE pe.server = %s AND
                            pe.dump_id > %s AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, num_av_labels, trusted_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.server = %s AND
                            dump_id > %s AND
                            p.corrupt='f') as b
                        ON a.min_id = b.dump_id
                    WHERE num_av_labels IS NULL""",
                                 (server, start_id, server, start_id))
            server_unknown_hashes = inner_cursor.fetchone()[0]
            db.server_unknown_hash[server] = server_unknown_hashes

# HOST


def get_host_total(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT host,count(host)
            FROM pe_dumps AS pe
            WHERE
                pe.dump_id > %d and host is not null
            GROUP BY host""" %
                       (start_id,))

    for row in cursor:
        if row is not None:
            db.domain_total_downloads[row[0]] = row[1]


def get_host_malware(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT host,count(host)
            FROM pe_dumps AS pe JOIN
                 ped_vts_mapping AS pvm USING (dump_id),
                 virus_total_scans AS vts
            WHERE
                pe.dump_id > %d AND
                vts.trusted_av_labels > 1 AND
                vts.vt_id = pvm.vt_id AND
                host is not null
            GROUP BY host""" %
                   (start_id,))

    for row in cursor:
        if row is not None:
            db.domain_malware_downloads[row[0]] = row[1]


def get_host_suspicious(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT host,count(host)
            FROM pe_dumps AS pe JOIN
                 ped_vts_mapping AS pvm USING (dump_id),
                 virus_total_scans AS vts
            WHERE
                pe.dump_id > %d AND
                vts.num_av_labels > 1 AND
                vts.vt_id = pvm.vt_id AND
                host is not null
            GROUP BY host""" %
                   (start_id,))

    for row in cursor:
        if row is not None:
            db.domain_suspicious_downloads[row[0]] = row[1]


def get_host_benign(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT host,count(host)
            FROM pe_dumps AS pe JOIN
                 ped_vts_mapping AS pvm USING (dump_id),
                 virus_total_scans AS vts
            WHERE
                pe.dump_id > %d AND
                vts.num_av_labels = 0 AND
                vts.vt_id = pvm.vt_id AND
                host is not null
            GROUP BY host""" %
                   (start_id,))

    for row in cursor:
        if row is not None:
            db.domain_benign_downloads[row[0]] = row[1]


def get_host_total_hashes(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()
    inner_cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT distinct host
                        FROM pe_dumps
                        WHERE dump_id > %d
                        and host is not null and corrupt = 'f'""" %
                   (start_id,))

    for row in cursor:
        if row is not None:
            host = row[0]
            inner_cursor.execute("""SELECT COUNT(DISTINCT pe.sha1)
                    FROM pe_dumps AS pe
                    WHERE pe.host = '%s' AND
                        pe.corrupt = 'f' AND
                        pe.dump_id > %d """ %
                                 (host, start_id))
            host_total_hashes = inner_cursor.fetchone()[0]
            db.domain_total_hash[host] = host_total_hashes


def get_host_unknown_hashes(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()
    inner_cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT distinct host
                        FROM pe_dumps
                        WHERE dump_id > %d
                        and host is not null and corrupt = 'f'""" %
                   (start_id,))

    for row in cursor:
        if row is not None:
            host = row[0]
            inner_cursor.execute("""SELECT COUNT(DISTINCT b.sha1)
                    FROM
                        (SELECT pe.sha1, MIN(dump_id) AS min_id
                        FROM pe_dumps AS pe
                        WHERE pe.host = %s AND
                            pe.dump_id > %s AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, num_av_labels, trusted_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.host = %s AND
                            dump_id > %s AND
                            p.corrupt='f') as b
                        ON a.min_id = b.dump_id
                    WHERE num_av_labels IS NULL""",
                                 (host, start_id, host, start_id))
            host_unknown_hashes = inner_cursor.fetchone()[0]
            db.domain_unknown_hash[host] = host_unknown_hashes


def get_server_percentage_error(db, feature_id, sketch):
    total_error = 0.0
    max_error = 0.0

    temp_tot = 0.0

    error_list = db_extraction.np.array([])
    # Init iterator
    iterator = db.server_total_downloads

    if(feature_id == 12):
        iterator = db.server_total_downloads.iteritems()
    elif(feature_id == 13):
        iterator = db.server_malware_downloads.iteritems()
    elif(feature_id == 14):
        iterator = db.server_suspicious_downloads.iteritems()
    elif(feature_id == 15):
        iterator = db.server_benign_downloads.iteritems()
    elif(feature_id == 16):
        iterator = db.server_malware_ratio.iteritems()
    elif(feature_id == 17):
        iterator = db.server_suspicious_ratio.iteritems()
    elif(feature_id == 18):
        iterator = db.server_benign_ratio.iteritems()
    elif(feature_id == 19):
        iterator = db.server_avg_av_labels.iteritems()
    elif(feature_id == 20):
        iterator = db.server_avg_trusted_labels.iteritems()
    elif(feature_id == 21):
        iterator = db.server_unknown_hash.iteritems()
    elif(feature_id == 22):
        iterator = db.server_total_hash.iteritems()
    elif(feature_id == 23):
        iterator = db.server_unknown_hash_ratio.iteritems()

    #  print db.server_malware_ratio

    for host, db_count in iterator:
        count_min_val = sketch.get(host)
        # print "Count_min_val %d" % count_min_val
        # print "Server %s" % host

        temp_tot += db_count

        difference = count_min_val - db_count
        if difference > max_error:
            max_error = difference
        if difference < 0:
            raise ValueError("Error: sketch counter lower than real value")

        error_list = db_extraction.np.append(error_list, difference)

        total_error += difference
    #print_results("server_total_downloads", "host", temp_tot, error_list, total_error, max_error)

    avg_error = db_extraction.np.mean(error_list)
    # print error_list
    mean_value = temp_tot / error_list.size

    error_rate = avg_error / mean_value * 100

    return error_rate


def get_domain_percentage_error(db, feature_id, sketch):
    total_error = 0.0
    max_error = 0.0

    temp_tot = 0.0

    error_list = db_extraction.np.array([])
    # Init iterator
    iterator = db.domain_total_downloads

    if(feature_id == 0):
        iterator = db.domain_total_downloads.iteritems()
    elif(feature_id == 1):
        iterator = db.domain_malware_downloads.iteritems()
    elif(feature_id == 2):
        iterator = db.domain_suspicious_downloads.iteritems()
    elif(feature_id == 3):
        iterator = db.domain_benign_downloads.iteritems()
    elif(feature_id == 4):
        iterator = db.domain_malware_ratio.iteritems()
    elif(feature_id == 5):
        iterator = db.domain_suspicious_ratio.iteritems()
    elif(feature_id == 6):
        iterator = db.domain_benign_ratio.iteritems()
    elif(feature_id == 7):
        iterator = db.domain_avg_av_labels.iteritems()
    elif(feature_id == 8):
        iterator = db.domain_avg_trusted_labels.iteritems()
    elif(feature_id == 9):
        iterator = db.domain_unknown_hash.iteritems()
    elif(feature_id == 10):
        iterator = db.domain_total_hash.iteritems()
    elif(feature_id == 11):
        iterator = db.domain_unknown_hash_ratio.iteritems()

    #  print db.domain_malware_ratio

    for host, db_count in iterator:
        count_min_val = sketch.get(host)
        # print "Count_min_val %d" % count_min_val
        # print "Host %s" % host

        temp_tot += db_count

        difference = count_min_val - db_count
        if difference > max_error:
            max_error = difference
        if difference < 0:
            raise ValueError("Error: sketch counter lower than real value")

        error_list = db_extraction.np.append(error_list, difference)

        total_error += difference
    #print_results("domain_total_downloads", "host", temp_tot, error_list, total_error, max_error)

    avg_error = db_extraction.np.mean(error_list)
    # print error_list
    mean_value = temp_tot / error_list.size

    error_rate = avg_error / mean_value * 100

    return error_rate


def get_bgp_percentage_error(db, feature_id, sketch):
    total_error = 0.0
    max_error = 0.0

    temp_tot = 0.0

    error_list = db_extraction.np.array([])
    # Init iterator
    iterator = db.bgp_total_downloads.iteritems()

    if(feature_id == 24):
        iterator = db.bgp_total_downloads.iteritems()
    elif(feature_id == 25):
        iterator = db.bgp_malware_downloads.iteritems()
    elif(feature_id == 26):
        iterator = db.bgp_suspicious_downloads.iteritems()
    elif(feature_id == 27):
        iterator = db.bgp_benign_downloads.iteritems()
    elif(feature_id == 28):
        iterator = db.bgp_malware_ratio.iteritems()
    elif(feature_id == 29):
        iterator = db.bgp_suspicious_ratio.iteritems()
    elif(feature_id == 30):
        iterator = db.bgp_benign_ratio.iteritems()
    elif(feature_id == 31):
        iterator = db.bgp_avg_av_labels.iteritems()
    elif(feature_id == 32):
        iterator = db.bgp_avg_trusted_labels.iteritems()
    elif(feature_id == 33):
        iterator = db.bgp_unknown_hash.iteritems()
    elif(feature_id == 34):
        iterator = db.bgp_total_hash.iteritems()
    elif(feature_id == 35):
        iterator = db.bgp_unknown_hash_ratio.iteritems()

    #  print db.domain_malware_ratio

    for bgp, db_count in iterator:
        count_min_val = sketch.get(bgp)

        temp_tot += db_count

        difference = count_min_val - db_count
        if difference > max_error:
            max_error = difference
        if difference < 0:
            raise ValueError("Error: sketch counter lower than real value")

        error_list = db_extraction.np.append(error_list, difference)

        total_error += difference
    #print_results("domain_total_downloads", "host", temp_tot, error_list, total_error, max_error)

    avg_error = db_extraction.np.mean(error_list)
    # print error_list
    mean_value = temp_tot / error_list.size

    error_rate = avg_error / mean_value * 100

    return error_rate


def get_twold_percentage_error(db, feature_id, sketch):
    total_error = 0.0
    max_error = 0.0

    temp_tot = 0.0

    error_list = db_extraction.np.array([])
    # Init iterator
    iterator = db.twold_total_downloads.iteritems()

    if(feature_id == 36):
        iterator = db.twold_total_downloads.iteritems()
    elif(feature_id == 37):
        iterator = db.twold_malware_downloads.iteritems()
    elif(feature_id == 38):
        iterator = db.twold_suspicious_downloads.iteritems()
    elif(feature_id == 39):
        iterator = db.twold_benign_downloads.iteritems()
    elif(feature_id == 40):
        iterator = db.twold_malware_ratio.iteritems()
    elif(feature_id == 41):
        iterator = db.twold_suspicious_ratio.iteritems()
    elif(feature_id == 42):
        iterator = db.twold_benign_ratio.iteritems()
    elif(feature_id == 43):
        iterator = db.twold_avg_av_labels.iteritems()
    elif(feature_id == 44):
        iterator = db.twold_avg_trusted_labels.iteritems()
    elif(feature_id == 45):
        iterator = db.twold_unknown_hash.iteritems()
    elif(feature_id == 46):
        iterator = db.twold_total_hash.iteritems()
    elif(feature_id == 47):
        iterator = db.twold_unknown_hash_ratio.iteritems()


    for twold, db_count in iterator:
        count_min_val = sketch.get(twold)

        temp_tot += db_count

        difference = count_min_val - db_count
        if difference > max_error:
            max_error = difference
        if difference < 0:
            raise ValueError("Error: sketch counter lower than real value")

        error_list = db_extraction.np.append(error_list, difference)

        total_error += difference

    avg_error = db_extraction.np.mean(error_list)
    # print error_list
    mean_value = temp_tot / error_list.size

    error_rate = avg_error / mean_value * 100

    return error_rate


def get_hash_percentage_error(db, feature_id, sketch):
    total_error = 0.0
    max_error = 0.0

    temp_tot = 0.0

    error_list = db_extraction.np.array([])
    # Init iterator
    iterator = db.hash_life_time.iteritems()

    if(feature_id == 48):
        iterator = db.hash_life_time.iteritems()
    elif(feature_id == 49):
        iterator = db.num_dumps_with_same_hash.iteritems()
    elif(feature_id == 50):
        iterator = db.hash_daily_dump_rate.iteritems()
    elif(feature_id == 51):
        iterator = db.estimated_clients_same_hash.iteritems()

    for sha1, db_count in iterator:
        count_min_val = sketch.get(sha1)

        temp_tot += db_count

        difference = count_min_val - db_count
        if difference > max_error:
            max_error = difference
        if difference < 0:
            raise ValueError("Error: sketch counter lower than real value ")

        error_list = db_extraction.np.append(error_list, difference)

        total_error += difference

    avg_error = db_extraction.np.mean(error_list)
    # print error_list
    mean_value = temp_tot / error_list.size

    error_rate = avg_error / mean_value * 100

    return error_rate


def get_url_percentage_error(db, feature_id, sketch):
    total_error = 0.0
    max_error = 0.0

    temp_tot = 0.0

    error_list = db_extraction.np.array([])
    # Init iterator
    iterator = db.url_malware_downloads

    if(feature_id == 52):
        iterator = db.url_malware_downloads.iteritems()
    elif(feature_id == 53):
        iterator = db.url_total_downloads.iteritems()
    elif(feature_id == 54):
        iterator = db.url_distinct_sha1s.iteritems()
    elif(feature_id == 55):
        iterator = db.url_struct_malware_downloads.iteritems()
    elif(feature_id == 56):
        iterator = db.url_struct_total_downloads.iteritems()
    elif(feature_id == 57):
        iterator = db.url_struct_distinct_sha1s.iteritems()

    for url, db_count in iterator:
        count_min_val = sketch.get(url)

        temp_tot += db_count

        difference = count_min_val - db_count
        if difference > max_error:
            max_error = difference
        if difference < 0:
            raise ValueError("Error: sketch counter lower than real value ")

        error_list = db_extraction.np.append(error_list, difference)

        total_error += difference

    avg_error = db_extraction.np.mean(error_list)
    # print error_list
    mean_value = temp_tot / error_list.size

    error_rate = avg_error / mean_value * 100

    return error_rate


def get_bgp_list(db, window):
    conn = db_extraction.util.connect_to_db()
    cursor = conn.cursor()
    inner_cursor = conn.cursor()

    start_id = db.maxID - window

    cursor.execute("""SELECT distinct server
        FROM pe_dumps AS pe
        WHERE
            pe.dump_id > %d and server is not null""" %
                   (start_id,))


    for row in cursor:
        if row is not None:
            server = row[0]
            inner_cursor.execute("""
                    SELECT bgp_prefix from bgp2asn where bgp_prefix >> %s""", (server,))
            inner_row = inner_cursor.fetchone()
            if inner_row is not None:
                bgp_prefix = inner_row[0]
                if bgp_prefix not in db.bgp_list:
                    db.bgp_list.append(bgp_prefix)
            else:
                continue
    print "BGP mapping computed!"


def get_percentage_error(db, feature_id, sketch):
    if(feature_id >= 0 and feature_id < 12):
        error_rate = get_domain_percentage_error(db, feature_id, sketch)
        return error_rate
    elif(feature_id >= 12 and feature_id < 24):
        error_rate = get_server_percentage_error(db, feature_id, sketch)
        return error_rate
    elif(feature_id >= 24 and feature_id < 36):
        error_rate = get_bgp_percentage_error(db, feature_id, sketch)
        return error_rate
    elif(feature_id >= 36 and feature_id < 48):
        error_rate = get_twold_percentage_error(db, feature_id, sketch)
        return error_rate
    elif(feature_id >= 48 and feature_id < 52):
        error_rate = get_hash_percentage_error(db, feature_id, sketch)
        return error_rate
    elif(feature_id >= 52 and feature_id < 58):
        error_rate = get_url_percentage_error(db, feature_id, sketch)
        return error_rate

