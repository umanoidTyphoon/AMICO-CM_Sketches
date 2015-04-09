from __future__ import division

__author__ = 'Vincenzo Deriu'

import util
import numpy as np
import urlparse
import re
import pickle


# noinspection PyStringFormat
class DBextraction:
    def __init__(self):

        conn = util.connect_to_db()
        cursor = conn.cursor()

        cursor.execute("""SELECT max(dump_id) from pe_dumps""")

        self.maxID = cursor.fetchone()[0]

        self.domain_total_downloads = {}
        self.domain_malware_downloads = {}
        self.domain_suspicious_downloads = {}
        self.domain_benign_downloads = {}
        self.domain_malware_ratio = {}
        self.domain_suspicious_ratio = {}
        self.domain_benign_ratio = {}
        self.domain_avg_av_labels = {}
        self.domain_avg_trusted_labels = {}
        self.domain_unknown_hash = {}
        self.domain_total_hash = {}
        self.domain_unknown_hash_ratio = {}

        self.server_total_downloads = {}
        self.server_malware_downloads = {}
        self.server_suspicious_downloads = {}
        self.server_benign_downloads = {}
        self.server_malware_ratio = {}
        self.server_suspicious_ratio = {}
        self.server_benign_ratio = {}
        self.server_avg_av_labels = {}
        self.server_avg_trusted_labels = {}
        self.server_unknown_hash = {}
        self.server_total_hash = {}
        self.server_unknown_hash_ratio = {}

        self.bgp_total_downloads = {}
        self.bgp_malware_downloads = {}
        self.bgp_suspicious_downloads = {}
        self.bgp_benign_downloads = {}
        self.bgp_malware_ratio = {}
        self.bgp_suspicious_ratio = {}
        self.bgp_benign_ratio = {}
        self.bgp_avg_av_labels = {}
        self.bgp_avg_trusted_labels = {}
        self.bgp_unknown_hash = {}
        self.bgp_total_hash = {}
        self.bgp_unknown_hash_ratio = {}

        self.twold_total_downloads = {}
        self.twold_malware_downloads = {}
        self.twold_suspicious_downloads = {}
        self.twold_benign_downloads = {}
        self.twold_malware_ratio = {}
        self.twold_suspicious_ratio = {}
        self.twold_benign_ratio = {}
        self.twold_avg_av_labels = {}
        self.twold_avg_trusted_labels = {}
        self.twold_unknown_hash = {}
        self.twold_total_hash = {}
        self.twold_unknown_hash_ratio = {}

        self.hash_life_time = {}
        self.num_dumps_with_same_hash = {}
        self.hash_daily_dump_rate = {}
        self.estimated_clients_same_hash = {}

        self.url_malware_downloads = {}
        self.url_total_downloads = {}
        self.url_distinct_sha1s = {}
        self.url_struct_malware_downloads = {}
        self.url_struct_total_downloads = {}
        self.url_struct_distinct_sha1s = {}

        self.host_twold_mapping = {}

        self.bgp_list = []

        self.twold_list = []

    # DOMAIN FEATURE EXTRACTION #
    def insert_host_total(self, s, window):
        """
        Insertion of feature domain_total_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT host,count(host)
            FROM pe_dumps AS pe
            WHERE
                pe.dump_id > %d and host is not null
            GROUP BY host""" %
                       (start_id,))

        for row in cursor:
            if row is not None:
                self.domain_total_downloads[row[0]] = row[1]
                s.update(row[0], row[1])

        # Build and return serialized object
        return util.serialize_sketch('host_total.p', s)

    def get_host_total(self, s):
        """
        Retrieving of feature domain_total_downloads
        """
        print "\nDOMAIN_TOTAL_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_total_downloads.iteritems(), s)

        print_results("domain_total_downloads", "host", temp_tot, error_list, total_error, max_error)

        return

    def insert_host_malware(self, s, window):
        """
        Insertion of feature domain_malware_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

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
                self.domain_malware_downloads[row[0]] = row[1]
                s.update(row[0], row[1])

        # Build and return serialized object
        return util.serialize_sketch('host_malware.p', s)

    def get_host_malware(self, s):
        """
        Retrieving of feature domain_malware_downloads
        """
        print "\nDOMAIN_MALWARE_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_malware_downloads.iteritems(), s)

        print_results("domain_malware_downloads", "host", temp_tot, error_list, total_error, max_error)

        return

    def insert_host_suspicious(self, s, window):
        """
        Insertion of feature domain_suspicious_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

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
                self.domain_suspicious_downloads[row[0]] = row[1]
                s.update(row[0], row[1])

        # Build and return serialized object
        return util.serialize_sketch('host_suspicious.p', s)

    def get_host_suspicious(self, s):
        """
        Retrieving of feature domain_suspicious_downloads
        """
        print "\nDOMAIN_SUSPICIOUS_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_suspicious_downloads.iteritems(), s)

        print_results("domain_suspicious_downloads", "host", temp_tot, error_list, total_error, max_error)

        return

    def insert_host_benign(self, s, window):
        """
        Insertion of feature domain_benign_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT host, count(host)
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
                self.domain_benign_downloads[row[0]] = row[1]
                s.update(row[0], row[1])

        # Build and return serialized object
        return util.serialize_sketch('host_benign.p', s)

    def get_host_benign(self, s):
        """
        Retrieving of feature domain_benign_downloads
        """
        print "\nDOMAIN_BENIGN_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_benign_downloads.iteritems(), s)

        print_results("domain_benign_downloads", "host", temp_tot, error_list, total_error, max_error)

        return

    def insert_host_malware_ratio(self, s):
        """
        Insertion of feature domain_malware_ratio
        """
        for host, db_count in self.domain_malware_downloads.iteritems():
            total_downloads = self.domain_total_downloads[host]

            ratio = float(db_count / total_downloads)
            self.domain_malware_ratio[host] = ratio
            s.update(host, ratio)

        # Build and return serialized object
        return util.serialize_sketch('host_malware_ratio.p', s)


    def get_host_malware_ratio(self, s):
        """
        Retrieving of feature domain_malware_ratio
        """
        print "\nDOMAIN_MALWARE_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_malware_ratio.iteritems(), s)

        print_results("domain_malware_ratio", "host", temp_tot, error_list, total_error, max_error)

        return

    def insert_host_suspicious_ratio(self, s):
        """
        Insertion of feature domain_suspicious_ratio
        """
        for host, db_count in self.domain_suspicious_downloads.iteritems():
            total_downloads = self.domain_total_downloads[host]

            ratio = float(db_count / total_downloads)
            self.domain_suspicious_ratio[host] = ratio
            s.update(host, ratio)

        return util.serialize_sketch('host_suspicious_ratio.p', s)

    def get_host_suspicious_ratio(self, s):
        """
        Retrieving of feature domain_suspicious_ratio
        """
        print "\nDOMAIN_SUSPICIOUS_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_suspicious_ratio.iteritems(), s)

        print_results("domain_suspicious_ratio", "host", temp_tot, error_list, total_error, max_error)

        return

    def insert_host_benign_ratio(self, s):
        """
        Insertion of feature domain_benign_ratio
        """
        for host, db_count in self.domain_benign_downloads.iteritems():
            total_downloads = self.domain_total_downloads[host]

            ratio = float(db_count / total_downloads)
            self.domain_benign_ratio[host] = ratio
            s.update(host, ratio)

        return util.serialize_sketch('host_benign_ratio.p', s)

    def get_host_benign_ratio(self, s):
        """
        Retrieving of feature domain_benign_ratio
        """
        print "\nDOMAIN_BENIGN_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_benign_ratio.iteritems(), s)

        print_results("domain_benign_ratio", "host", temp_tot, error_list, total_error, max_error)

        return

    def insert_host_avg_av_labels(self, s, window):
        """
        Insertion of feature domain_avg_av_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct host
                        FROM pe_dumps
                        WHERE dump_id > %d
                        and host is not null and corrupt = 'f'""" %
                       (start_id,))

        for row in cursor:
            if row is not None:
                host = row[0]
                inner_cursor.execute("""
                    SELECT AVG(num_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
                        FROM pe_dumps AS pe
                        WHERE pe.host = '%s' AND
                            pe.dump_id > %d AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, num_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.host = '%s' AND
                            dump_id > %d AND
                            p.corrupt='f') as b
                        ON a.max_id = b.dump_id
                    WHERE b.num_av_labels IS NOT NULL""" %
                                     (host, start_id, host, start_id))
                if inner_cursor.rowcount > 0:
                    averages = inner_cursor.fetchone()
                    avg_av = averages[0]
                    if avg_av is not None:
                        avg_av = float(avg_av)
                        self.domain_avg_av_labels[host] = avg_av
                        s.update(host, avg_av)

        return util.serialize_sketch('host_avg_av_labels.p', s)

    def insert_host_avg_trusted_labels(self, s, window):
        """
        Insertion of feature domain_avg_trusted_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct host
                        FROM pe_dumps
                        WHERE dump_id > %d
                        and host is not null and corrupt = 'f'""" %
                       (start_id,))

        for row in cursor:
            if row is not None:
                host = row[0]
                inner_cursor.execute("""
                    SELECT AVG(trusted_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
                        FROM pe_dumps AS pe
                        WHERE pe.host = '%s' AND
                            pe.dump_id > %d AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, trusted_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.host = '%s' AND
                            dump_id > %d AND
                            p.corrupt='f') as b
                        ON a.max_id = b.dump_id
                    WHERE b.trusted_av_labels IS NOT NULL""" %
                                     (host, start_id, host, start_id))
                if inner_cursor.rowcount > 0:
                    averages = inner_cursor.fetchone()
                    avg_trusted = averages[0]
                    if avg_trusted is not None:
                        avg_trusted = float(avg_trusted)
                        self.domain_avg_trusted_labels[host] = avg_trusted
                        s.update(host, avg_trusted)

        return util.serialize_sketch('host_avg_trusted_labels.p', s)

    def insert_host_avg_av_labels_trusted_labels(self, s1, s2, window):
        """
        Insertion of feature domain_avg_av_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct host
                        FROM pe_dumps
                        WHERE dump_id > %d
                        and host is not null and corrupt = 'f'""" %
                       (start_id,))

        for row in cursor:
            if row is not None:
                host = row[0]
                inner_cursor.execute("""
                    SELECT AVG(num_av_labels), AVG(trusted_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
                        FROM pe_dumps AS pe
                        WHERE pe.host = '%s' AND
                            pe.dump_id > %d AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, num_av_labels, trusted_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.host = '%s' AND
                            dump_id > %d AND
                            p.corrupt='f') as b
                        ON a.max_id = b.dump_id
                    WHERE b.num_av_labels IS NOT NULL""" %
                                     (host, start_id, host, start_id))
                if inner_cursor.rowcount > 0:
                    averages = inner_cursor.fetchone()
                    avg_av = averages[0]
                    avg_trusted = averages[1]
                    if avg_av is not None:
                        avg_av = float(avg_av)
                        self.domain_avg_av_labels[host] = avg_av
                        s1.update(host, avg_av)
                    if avg_trusted is not None:
                        avg_trusted = float(avg_trusted)
                        self.domain_avg_trusted_labels[host] = avg_trusted
                        s2.update(host, avg_trusted)

        return util.serialize_sketch('host_avg_av_labels.p', s1), util.serialize_sketch('host_avg_trusted_labels.p', s2)

    def get_host_avg_av_labels_trusted_labels(self, s1, s2):
        """
        Retrieving of feature domain_avg_av_labels and domain avg_trusted_labels
        """
        print "\nDOMAIN_AVG_AV_LABELS_TRUSTED_LABELS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_avg_av_labels.iteritems(), s1)

        print_results("domain_avg_av_labels", "host", temp_tot, error_list, total_error, max_error)

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_avg_trusted_labels.iteritems(), s2)

        print_results("domain_avg_trusted_labels", "host", temp_tot, error_list, total_error, max_error)

        return

    def insert_host_unknown_hashes(self, s, window):
        """
        Insertion of feature domain_unknown_hashes
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

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
                self.domain_unknown_hash[host] = host_unknown_hashes
                s.update(host, host_unknown_hashes)

        return util.serialize_sketch('host_unknown_hash.p', s)

    def get_host_unknown_hashes(self, s):
        """
        Retrieving of feature domain_unknown_hashes
        """
        print "\nDOMAIN_UNKNOWN_HASHES:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_unknown_hash.iteritems(), s)

        print_results("domain_unknown_hashes", "host", temp_tot, error_list, total_error, max_error)

        return

    def insert_host_total_hashes(self, s, window):
        """
        Insertion of feature domain_total_hashes
        """

        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

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
                self.domain_total_hash[host] = host_total_hashes
                s.update(host, host_total_hashes)

        return util.serialize_sketch('host_total_hash.p', s)

    def get_host_total_hashes(self, s):
        """
        Retrieving of feature domain_total_hashes
        """
        print "\nDOMAIN_TOTAL_HASHES:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_total_hash.iteritems(), s)

        print_results("domain_total_hashes", "host", temp_tot, error_list, total_error, max_error)

        return

    def insert_host_unknown_hash_ratio(self, s):
        """
        Insertion of feature domain_host_unknown_hash_ratio
        """
        for host, host_unknown_hashes in self.domain_unknown_hash.iteritems():
            host_total_hashes = self.domain_total_hash[host]

            ratio = float(host_unknown_hashes / host_total_hashes)
            self.domain_unknown_hash_ratio[host] = ratio
            s.update(host, ratio)

        return util.serialize_sketch('host_unknown_hash_ratio.p', s)

    def get_host_unknown_hash_ratio(self, s):
        """
        Retrieving of feature domain_host_unknown_hash_ratio
        """
        print "\nDOMAIN_UNKNOWN_HASH_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.domain_unknown_hash_ratio.iteritems(), s)

        print_results("domain_unknown_hash_ratio", "host", temp_tot, error_list, total_error, max_error)

        return

    # SERVER FEATURES EXTRACTION #
    def insert_server_total(self, s, window):
        """
        Insertion of feature server_total_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT server,count(server)
            FROM pe_dumps AS pe
            WHERE
                pe.dump_id > %d and server is not null
            GROUP BY server""" %
                       (start_id,))

        for row in cursor:
            if row is not None:
                self.server_total_downloads[row[0]] = row[1]
                s.update(row[0], row[1])

        return util.serialize_sketch('server_total.p', s)

    def get_server_total(self, s):
        """
        Retrieving of feature server_total_downloads
        """
        print "\nSERVER_TOTAL_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_total_downloads.iteritems(), s)

        print_results("server_total_downloads", "server", temp_tot, error_list, total_error, max_error)

        return

    def insert_server_malware(self, s, window):
        """
        Insertion of feature server_malware_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

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
                self.server_malware_downloads[row[0]] = row[1]
                s.update(row[0], row[1])

        return util.serialize_sketch('server_malware.p', s)

    def get_server_malware(self, s):
        """
        Retrieving of feature server_malware_downloads
        """
        print "\nSERVER_MALWARE_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_malware_downloads.iteritems(), s)

        print_results("server_malware_downloads", "server", temp_tot, error_list, total_error, max_error)

        return

    def insert_server_suspicious(self, s, window):
        """
        Insertion of feature server_suspicious_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

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
                self.server_suspicious_downloads[row[0]] = row[1]
                s.update(row[0], row[1])

        return util.serialize_sketch('server_suspicious.p', s)

    def get_server_suspicious(self, s):
        """
        Retrieving of feature server_suspicious_downloads
        """
        print "\nSERVER_SUSPICIOUS_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_suspicious_downloads.iteritems(), s)

        print_results("server_suspicious_downloads", "server", temp_tot, error_list, total_error, max_error)

        return

    def insert_server_benign(self, s, window):
        """
        Insertion of feature server_benign_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

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
                self.server_benign_downloads[row[0]] = row[1]
                s.update(row[0], row[1])

        return util.serialize_sketch('server_benign.p', s)

    def get_server_benign(self, s):
        """
        Retrieving of feature server_benign_downloads
        """
        print "\nSERVER_BENIGN_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_benign_downloads.iteritems(), s)

        print_results("server_benign_downloads", "server", temp_tot, error_list, total_error, max_error)

        return

    def insert_server_malware_ratio(self, s):
        """
        Insertion of feature server_malware_ratio
        """
        for server, db_count in self.server_malware_downloads.iteritems():
            total_downloads = self.server_total_downloads[server]

            ratio = float(db_count / total_downloads)
            self.server_malware_ratio[server] = ratio
            s.update(server, ratio)

        return util.serialize_sketch('server_malware_ratio.p', s)

    def get_server_malware_ratio(self, s):
        """
        Retrieving of feature server_malware_ratio
        """
        print "\nSERVER_MALWARE_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_malware_ratio.iteritems(), s)

        print_results("server_malware_ratio", "server", temp_tot, error_list, total_error, max_error)

        return

    def insert_server_suspicious_ratio(self, s):
        """
        Insertion of feature server_suspicious_ratio
        """
        for server, db_count in self.server_suspicious_downloads.iteritems():
            total_downloads = self.server_total_downloads[server]

            ratio = float(db_count / total_downloads)
            self.server_suspicious_ratio[server] = ratio
            s.update(server, ratio)

        return util.serialize_sketch('server_suspicious_ratio.p', s)

    def get_server_suspicious_ratio(self, s):
        """
        Retrieving of feature server_suspicious_ratio
        """
        print "\nSERVER_SUSPICIOUS_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_suspicious_ratio.iteritems(), s)

        print_results("server_suspicious_ratio", "server", temp_tot, error_list, total_error, max_error)

        return

    def insert_server_benign_ratio(self, s):
        """
        Insertion of feature server_benign_ratio
        """
        for server, db_count in self.server_benign_downloads.iteritems():
            total_downloads = self.server_total_downloads[server]

            ratio = float(db_count / total_downloads)
            self.server_benign_ratio[server] = ratio
            s.update(server, ratio)

        return util.serialize_sketch('server_benign_ratio.p', s)

    def get_server_benign_ratio(self, s):
        """
        Retrieving of feature server_benign_ratio
        """
        print "\nSERVER_BENIGN_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_benign_ratio.iteritems(), s)

        print_results("server_benign_ratio", "server", temp_tot, error_list, total_error, max_error)

        return

    def insert_server_avg_av_labels(self, s, window):
        """
        Insertion of feature server_avg_av_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct server
                        FROM pe_dumps
                        WHERE dump_id > %d
                        and server is not null and corrupt = 'f'""" %
                       (start_id,))

        for row in cursor:
            if row is not None:
                server = row[0]
                inner_cursor.execute("""
                    SELECT AVG(num_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
                        FROM pe_dumps AS pe
                        WHERE pe.server = '%s' AND
                            pe.dump_id > %d AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, num_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.server = '%s' AND
                            dump_id > %d AND
                            p.corrupt='f') as b
                        ON a.max_id = b.dump_id
                    WHERE b.num_av_labels IS NOT NULL""" %
                                     (server, start_id, server, start_id))
                if inner_cursor.rowcount > 0:
                    averages = inner_cursor.fetchone()
                    avg_av = averages[0]
                    if avg_av is not None:
                        avg_av = float(avg_av)
                        self.server_avg_av_labels[server] = avg_av
                        s.update(server, avg_av)

        return util.serialize_sketch('server_avg_av_labels.p', s)

    def insert_server_avg_trusted_labels(self, s, window):
        """
        Insertion of feature server_avg_av_labels and server avg_trusted_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct server
                        FROM pe_dumps
                        WHERE dump_id > %d
                        and server is not null and corrupt = 'f'""" %
                       (start_id,))

        for row in cursor:
            if row is not None:
                server = row[0]
                inner_cursor.execute("""
                    SELECT AVG(trusted_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
                        FROM pe_dumps AS pe
                        WHERE pe.server = '%s' AND
                            pe.dump_id > %d AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, trusted_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.server = '%s' AND
                            dump_id > %d AND
                            p.corrupt='f') as b
                        ON a.max_id = b.dump_id
                    WHERE b.trusted_av_labels IS NOT NULL""" %
                                     (server, start_id, server, start_id))
                if inner_cursor.rowcount > 0:
                    averages = inner_cursor.fetchone()
                    avg_trusted = averages[0]
                    if avg_trusted is not None:
                        avg_trusted = float(avg_trusted)
                        self.server_avg_trusted_labels[server] = avg_trusted
                        s.update(server, avg_trusted)

        return util.serialize_sketch('server_avg_trusted_labels.p', s)

    def insert_server_avg_av_labels_trusted_labels(self, s1, s2, window):
        """
        Insertion of feature server_avg_av_labels and server avg_trusted_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct server
                        FROM pe_dumps
                        WHERE dump_id > %d
                        and server is not null and corrupt = 'f'""" %
                       (start_id,))

        for row in cursor:
            if row is not None:
                server = row[0]
                inner_cursor.execute("""
                    SELECT AVG(num_av_labels), AVG(trusted_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
                        FROM pe_dumps AS pe
                        WHERE pe.server = '%s' AND
                            pe.dump_id > %d AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, num_av_labels, trusted_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.server = '%s' AND
                            dump_id > %d AND
                            p.corrupt='f') as b
                        ON a.max_id = b.dump_id
                    WHERE b.num_av_labels IS NOT NULL""" %
                                     (server, start_id, server, start_id))
                if inner_cursor.rowcount > 0:
                    averages = inner_cursor.fetchone()
                    avg_av = averages[0]
                    avg_trusted = averages[1]
                    if avg_av is not None:
                        avg_av = float(avg_av)
                        self.server_avg_av_labels[server] = avg_av
                        s1.update(server, avg_av)
                    if avg_trusted is not None:
                        avg_trusted = float(avg_trusted)
                        self.server_avg_trusted_labels[server] = avg_trusted
                        s2.update(server, avg_trusted)

        return util.serialize_sketch('server_avg_av_labels.p', s1), util.serialize_sketch('server_avg_trusted_labels.p',
                                                                                          s2)

    def get_server_avg_av_labels_trusted_labels(self, s1, s2):
        """
        Retrieving of feature server_avg_av_labels and server avg_trusted_labels
        """
        print "\nSERVER_AVG_AV_LABELS_TRUSTED_LABELS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_avg_av_labels.iteritems(), s1)

        print_results("server_avg_av_labels", "server", temp_tot, error_list, total_error, max_error)

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_avg_trusted_labels.iteritems(), s2)

        print_results("server_avg_trusted_labels", "server", temp_tot, error_list, total_error,  max_error)

        return

    def insert_server_unknown_hashes(self, s, window):
        """
        Insertion of feature server_unknown_hashes
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

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
                self.server_unknown_hash[server] = server_unknown_hashes
                s.update(server, server_unknown_hashes)

        return util.serialize_sketch('server_unknown_hashes.p', s)

    def get_server_unknown_hashes(self, s):
        """
        Retrieving of feature server_unknown_hashes
        """
        print "\nSERVER_UNKNOWN_HASHES:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_unknown_hash.iteritems(), s)

        print_results("server_unknown_hashes", "server", temp_tot, error_list, total_error, max_error)

        return

    def insert_server_total_hashes(self, s, window):
        """
        Insertion of feature server_total_hashes
        """

        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

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
                self.server_total_hash[server] = server_total_hashes
                s.update(server, server_total_hashes)

        return util.serialize_sketch('server_total_hashes.p', s)

    def get_server_total_hashes(self, s):
        """
        Retrieving of feature server_total_hashes
        """
        print "\nSERVER_TOTAL_HASHES:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_total_hash.iteritems(), s)

        print_results("server_total_hashes", "server", temp_tot, error_list, total_error, max_error)

        return

    def insert_server_unknown_hash_ratio(self, s):
        """
        Insertion of feature server_server_unknown_hash_ratio
        """
        for server, server_unknown_hashes in self.server_unknown_hash.iteritems():
            server_total_hashes = self.server_total_hash[server]

            ratio = float(server_unknown_hashes / server_total_hashes)
            self.server_unknown_hash_ratio[server] = ratio
            s.update(server, ratio)

        return util.serialize_sketch('server_unknown_hash_ratio.p', s)

    def get_server_unknown_hash_ratio(self, s):
        """
        Retrieving of feature server_server_unknown_hash_ratio
        """
        print "\nSERVER_UNKNOWN_HASH_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.server_unknown_hash_ratio.iteritems(), s)

        print_results("server_unknown_hash_ratio", "server", temp_tot, error_list, total_error, max_error)

        return

    # BGP FEATURES EXTRACTION
    def insert_bgp_total(self, s, window):
        """
        Insertion of feature bgp_total_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

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
                    if bgp_prefix not in self.bgp_list:
                        self.bgp_list.append(bgp_prefix)
                else:
                    continue

        for bgp in self.bgp_list:
            inner_cursor.execute("""
                    SELECT COUNT(DISTINCT dump_id)
                    FROM pe_dumps AS pe
                    WHERE pe.server << %s AND
                        pe.dump_id > %s""",
                                 (bgp, start_id))
            bgp_total_downloads = inner_cursor.fetchone()[0]
            self.bgp_total_downloads[bgp] = bgp_total_downloads
            s.update(bgp, bgp_total_downloads)

        return util.serialize_sketch('bgp_total.p', s)

    def get_bgp_total(self, s):
        """
        Retrieving of feature bgp_total_downloads
        """
        print "\nBGP_TOTAL_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_total_downloads.iteritems(), s)

        print_results("bgp_total_downloads", "bgp", temp_tot, error_list, total_error, max_error)

        return

    def insert_bgp_malware(self, s, window):
        """
        Insertion of feature bgp_malware_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for bgp in self.bgp_list:
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
            self.bgp_malware_downloads[bgp] = bgp_malware_downloads
            s.update(bgp, bgp_malware_downloads)

        return util.serialize_sketch('bgp_malware.p', s)

    def get_bgp_malware(self, s):
        """
        Retrieving of feature bgp_malware_downloads
        """
        print "\nBGP_MALWARE_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_malware_downloads.iteritems(), s)

        print_results("bgp_malware_downloads", "bgp", temp_tot, error_list, total_error, max_error)

        return

    def insert_bgp_suspicious(self, s, window):
        """
        Insertion of feature bgp_suspicious_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for bgp in self.bgp_list:
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
            self.bgp_suspicious_downloads[bgp] = bgp_suspicious_downloads
            s.update(bgp, bgp_suspicious_downloads)

        return util.serialize_sketch('bgp_suspicious.p', s)

    def get_bgp_suspicious(self, s):
        """
        Retrieving of feature bgp_suspicious_downloads

        """
        print "\nBGP_SUSPICIOUS_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_suspicious_downloads.iteritems(), s)

        print_results("bgp_suspicious_downloads", "bgp", temp_tot, error_list, total_error, max_error)

        return

    def insert_bgp_benign(self, s, window):
        """
        Insertion of feature bgp_benign_downloads

        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for bgp in self.bgp_list:
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
            self.bgp_benign_downloads[bgp] = bgp_benign_downloads
            s.update(bgp, bgp_benign_downloads)

        return util.serialize_sketch('bgp_benign.p', s)

    def get_bgp_benign(self, s):
        """
        Retrieving of feature bgp_benign_downloads
        """
        print "\nBGP_BENIGN_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_benign_downloads.iteritems(), s)

        print_results("bgp_benign_downloads", "bgp", temp_tot, error_list, total_error, max_error)

        return

    def insert_bgp_malware_ratio(self, s):
        for bgp, bgp_malware_downloads in self.bgp_malware_downloads.iteritems():
            bgp_total_downloads = self.bgp_total_downloads[bgp]
            ratio = float(bgp_malware_downloads / bgp_total_downloads)
            self.bgp_malware_ratio[bgp] = ratio
            s.update(bgp, ratio)

        return util.serialize_sketch('bgp_malware_ratio.p', s)

    def get_bgp_malware_ratio(self, s):
        """
        Retrieving of feature bgp_malware_ratio
        """
        print "\nBGP_MALWARE_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_malware_ratio.iteritems(), s)

        print_results("bgp_malware_ratio", "bgp", temp_tot, error_list, total_error, max_error)

        return

    def insert_bgp_suspicious_ratio(self, s):
        for bgp, bgp_suspicious_downloads in self.bgp_suspicious_downloads.iteritems():
            bgp_total_downloads = self.bgp_total_downloads[bgp]
            ratio = float(bgp_suspicious_downloads / bgp_total_downloads)
            self.bgp_suspicious_ratio[bgp] = ratio
            s.update(bgp, ratio)

        return util.serialize_sketch('bgp_suspicious_ratio.p', s)

    def get_bgp_suspicious_ratio(self, s):
        """
        Retrieving of feature bgp_suspicious_ratio
        """
        print "\nBGP_SUSPICIOUS_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_suspicious_ratio.iteritems(), s)

        print_results("bgp_suspicious_ratio", "bgp", temp_tot, error_list, total_error, max_error)

        return

    def insert_bgp_benign_ratio(self, s):
        for bgp, bgp_benign_downloads in self.bgp_benign_downloads.iteritems():
            bgp_total_downloads = self.bgp_total_downloads[bgp]
            ratio = float(bgp_benign_downloads / bgp_total_downloads)
            self.bgp_benign_ratio[bgp] = ratio
            s.update(bgp, ratio)

        return util.serialize_sketch('bgp_benign_ratio.p', s)

    def get_bgp_benign_ratio(self, s):
        """
        Retrieving of feature bgp_benign_ratio
        """
        print "\nBGP_BENIGN_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_benign_ratio.iteritems(), s)

        print_results("bgp_benign_ratio", "bgp", temp_tot, error_list, total_error, max_error)

        return

    def insert_bgp_avg_av_labels(self, s, window):
        """
        Insertion of feature bgp_avg_av_labels and bgp avg_trusted_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for bgp in self.bgp_list:
            cursor.execute("""SELECT AVG(num_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
                        FROM pe_dumps AS pe
                        WHERE pe.server << %s AND
                            pe.dump_id > %s AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, num_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.server << %s AND
                            dump_id > %s AND
                            p.corrupt='f') as b
                        ON a.max_id = b.dump_id
                    WHERE num_av_labels IS NOT NULL""",
                           (bgp, start_id, bgp, start_id))
            if cursor.rowcount > 0:
                averages = cursor.fetchone()
                avg_av = averages[0]
                if avg_av is not None:
                    avg_av = float(avg_av)
                    self.bgp_avg_av_labels[bgp] = avg_av
                    s.update(bgp, avg_av)

        return util.serialize_sketch('bgp_avg_av_labels.p', s)

    def insert_bgp_avg_trusted_labels(self, s, window):
        """
        Insertion of feature bgp avg_trusted_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for bgp in self.bgp_list:
            cursor.execute("""SELECT AVG(trusted_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
                        FROM pe_dumps AS pe
                        WHERE pe.server << %s AND
                            pe.dump_id > %s AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, trusted_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.server << %s AND
                            dump_id > %s AND
                            p.corrupt='f') as b
                        ON a.max_id = b.dump_id
                    WHERE trusted_av_labels IS NOT NULL""",
                           (bgp, start_id, bgp, start_id))
            if cursor.rowcount > 0:
                averages = cursor.fetchone()
                avg_trusted = averages[0]
                if avg_trusted is not None:
                    avg_trusted = float(avg_trusted)
                    self.bgp_avg_trusted_labels[bgp] = avg_trusted
                    s.update(bgp, avg_trusted)

        return util.serialize_sketch('bgp_avg_trusted_labels.p', s)

    def insert_bgp_avg_av_labels_trusted_labels(self, s1, s2, window):
        """
        Insertion of feature bgp_avg_av_labels and bgp avg_trusted_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for bgp in self.bgp_list:
            cursor.execute("""SELECT AVG(num_av_labels), AVG(trusted_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
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
                        ON a.max_id = b.dump_id
                    WHERE num_av_labels IS NOT NULL""",
                           (bgp, start_id, bgp, start_id))
            if cursor.rowcount > 0:
                averages = cursor.fetchone()
                avg_av = averages[0]
                avg_trusted = averages[1]
                if avg_av is not None:
                    avg_av = float(avg_av)
                    self.bgp_avg_av_labels[bgp] = avg_av
                    s1.update(bgp, avg_av)
                if avg_trusted is not None:
                    avg_trusted = float(avg_trusted)
                    self.bgp_avg_trusted_labels[bgp] = avg_trusted
                    s2.update(bgp, avg_trusted)

        return util.serialize_sketch('bgp_avg_av_labels.p', s1), util.serialize_sketch('bgp_avg_trusted_labels.p', s2)

    def get_bgp_avg_av_labels_trusted_labels(self, s1, s2):
        """
        Retrieving of feature bgp_avg_av_labels and bgp avg_trusted_labels
        """
        print "\nBGP_AVG_AV_LABELS_TRUSTED_LABELS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_avg_av_labels.iteritems(), s1)

        print_results("bgp_avg_av_labels", "bgp", temp_tot, error_list, total_error, max_error)

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_avg_trusted_labels.iteritems(), s2)

        print_results("bgp_avg_trusted_labels", "bgp", temp_tot, error_list, total_error, max_error)

        return

    def insert_bgp_unknown_hashes(self, s, window):
        """
        Insertion of feature bgp_unknown_hashes
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for bgp in self.bgp_list:
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
            self.bgp_unknown_hash[bgp] = bgp_unknown_hashes
            s.update(bgp, bgp_unknown_hashes)

        return util.serialize_sketch('bgp_unknown_hashes.p', s)

    def get_bgp_unknown_hashes(self, s):
        """
        Retrieving of feature bgp_unknown_hashes
        """
        print "\nBGP_UNKNOWN_HASHES:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_unknown_hash.iteritems(), s)

        print_results("bgp_unknown_hashes", "bgp", temp_tot, error_list, total_error, max_error)

        return

    def insert_bgp_total_hashes(self, s, window):
        """
        Insertion of feature bgp_total_hashes
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for bgp in self.bgp_list:
            cursor.execute("""
                SELECT COUNT(DISTINCT pe.sha1)
                FROM pe_dumps AS pe
                WHERE pe.server << %s AND
                    pe.corrupt = 'f' AND
                    pe.dump_id > %s """,
                           (bgp, start_id))
            bgp_total_hashes = cursor.fetchone()[0]
            self.bgp_total_hash[bgp] = bgp_total_hashes
            s.update(bgp, bgp_total_hashes)

        return util.serialize_sketch('bgp_total_hash.p', s)

    def get_bgp_total_hashes(self, s):
        """
        Retrieving of feature bgp_total_hashes
        """
        print "\nBGP_TOTAL_HASHES:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_total_hash.iteritems(), s)

        print_results("bgp_total_hashes", "bgp", temp_tot, error_list, total_error, max_error)

        return

    def insert_bgp_unknown_hash_ratio(self, s):
        """
        Insertion of feature bgp_unknown_hash_ratio

        """
        for bgp, bgp_unknown_hashes in self.bgp_unknown_hash.iteritems():
            bgp_total_hashes = self.bgp_total_hash[bgp]
            if bgp_total_hashes == 0:
                continue
            ratio = float(bgp_unknown_hashes / bgp_total_hashes)

            self.bgp_unknown_hash_ratio[bgp] = ratio
            s.update(bgp, ratio)

        return util.serialize_sketch('bgp_unknown_hash_ratio.p', s)

    def get_bgp_unknown_hash_ratio(self, s):
        """
        Retrieving of feature bgp_unknown_hash_ratio
        """
        print "\nBGP_UNKNOWN_HASH_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.bgp_unknown_hash_ratio.iteritems(), s)

        print_results("bgp_unknown_hash_ratio", "bgp", temp_tot, error_list, total_error, max_error)

        return

    # 2LD FEATURE EXTRACTION #
    def insert_twold_total(self, s, window):
        """
        Insertion of feature 2ld_total_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for twold in self.twold_list:
            cursor.execute("""
                SELECT COUNT(DISTINCT dump_id)
                FROM pe_dumps AS pe
                WHERE pe.host LIKE %s AND
                    pe.dump_id > %s""",
                           (twold, start_id))

            twold_total_downloads = cursor.fetchone()[0]
            self.twold_total_downloads[twold] = twold_total_downloads
            s.update(twold, twold_total_downloads)

        return util.serialize_sketch('twold_total.p', s)

    def get_twold_total(self, s):
        """
        Retrieving of feature 2ld_total_downloads
        """
        print "\n2LD_TOTAL_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_total_downloads.iteritems(), s)

        print_results("2ld_total_downloads", "twold", temp_tot, error_list, total_error, max_error)

        return

    def insert_twold_malware(self, s, window):
        """
        Insertion of feature 2ld_malware_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for twold in self.twold_list:
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
            self.twold_malware_downloads[twold] = twold_malware_downloads
            s.update(twold, twold_malware_downloads)

        return util.serialize_sketch('twold_malware.p', s)

    def get_twold_malware(self, s):
        """
        Retrieving of feature 2ld_malware_downloads
        """
        print "\n2LD_MALWARE_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_malware_downloads.iteritems(), s)

        print_results("2ld_malware_downloads", "twold", temp_tot, error_list, total_error, max_error)

        return

    def insert_twold_suspicious(self, s, window):
        """
        Insertion of feature 2ld_suspicious_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for twold in self.twold_list:
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
            self.twold_suspicious_downloads[twold] = twold_suspicious_downloads
            s.update(twold, twold_suspicious_downloads)

        return util.serialize_sketch('twold_suspicious.p', s)

    def get_twold_suspicious(self, s):
        """
        Retrieving of feature 2ld_suspicious_downloads
        """
        print "\n2LD_SUSPICIOUS_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_suspicious_downloads.iteritems(), s)

        print_results("2ld_suspicious_downloads", "twold", temp_tot, error_list, total_error, max_error)

        return

    def insert_twold_benign(self, s, window):
        """
        Insertion of feature 2ld_benign_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for twold in self.twold_list:
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
            self.twold_benign_downloads[twold] = twold_benign_downloads
            s.update(twold, twold_benign_downloads)

        return util.serialize_sketch('twold_benign.p', s)

    def get_twold_benign(self, s):
        """
        Retrieving of feature 2ld_benign_downloads
        """
        print "\n2LD_BENIGN_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_benign_downloads.iteritems(), s)

        print_results("2ld_benign_downloads", "twold", temp_tot, error_list, total_error, max_error)

        return

    def insert_twold_malware_ratio(self, s):
        for twold, twold_malware_downloads in self.twold_malware_downloads.iteritems():
            twold_total_downloads = self.twold_total_downloads[twold]
            ratio = float(twold_malware_downloads / twold_total_downloads)
            self.twold_malware_ratio[twold] = ratio
            s.update(twold, ratio)

        return util.serialize_sketch('twold_malware_ratio.p', s)

    def get_twold_malware_ratio(self, s):
        """
        Retrieving of feature twold_malware_ratio
        """
        print "\nTWOLD_MALWARE_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_malware_ratio.iteritems(), s)

        print_results("2ld_malware_ratio", "twold", temp_tot, error_list, total_error, max_error)

        return

    def insert_twold_suspicious_ratio(self, s):
        for twold, twold_suspicious_downloads in self.twold_suspicious_downloads.iteritems():
            twold_total_downloads = self.twold_total_downloads[twold]
            ratio = float(twold_suspicious_downloads / twold_total_downloads)
            self.twold_suspicious_ratio[twold] = ratio
            s.update(twold, ratio)

        return util.serialize_sketch('twold_suspicious_ratio.p', s)

    def get_twold_suspicious_ratio(self, s):
        """
        Retrieving of feature twold_suspicious_ratio
        """
        print "\nTWOLD_SUSPICIOS_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_suspicious_ratio.iteritems(), s)

        print_results("2ld_suspicious_ratio", "twold", temp_tot, error_list, total_error, max_error)

        return

    def insert_twold_benign_ratio(self, s):
        for twold, twold_benign_downloads in self.twold_benign_downloads.iteritems():
            twold_total_downloads = self.twold_total_downloads[twold]
            ratio = float(twold_benign_downloads / twold_total_downloads)
            self.twold_benign_ratio[twold] = ratio
            s.update(twold, ratio)

        return util.serialize_sketch('twold_benign_ratio.p', s)

    def get_twold_benign_ratio(self, s):
        """
        Retrieving of feature twold_benign_ratio
        """
        print "\nTWOLD_BENIGN_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_benign_ratio.iteritems(), s)

        print_results("2ld_benign_ratio", "twold", temp_tot, error_list, total_error, max_error)

        return

    def insert_twold_avg_av_labels(self, s, window):
        """
        Insertion of feature twold_avg_av_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for twold in self.twold_list:

            cursor.execute("""SELECT AVG(num_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
                        FROM pe_dumps AS pe
                        WHERE pe.host LIKE %s AND
                            pe.dump_id > %s AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, num_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.host LIKE %s AND
                            dump_id > %s AND
                            p.corrupt='f') as b
                        ON a.max_id = b.dump_id
                    WHERE num_av_labels IS NOT NULL""",
                           (twold, start_id, twold, start_id))
            if cursor.rowcount > 0:
                averages = cursor.fetchone()
                avg_av = averages[0]
                if avg_av is not None:
                    avg_av = float(avg_av)
                    self.twold_avg_av_labels[twold] = avg_av
                    s.update(twold, avg_av)

        return util.serialize_sketch('twold_avg_av_labels.p', s)

    def insert_twold_avg_trusted_labels(self, s, window):
        """
        Insertion of feature twold_avg_av_labels and bgp avg_trusted_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for twold in self.twold_list:

            cursor.execute("""SELECT AVG(trusted_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
                        FROM pe_dumps AS pe
                        WHERE pe.host LIKE %s AND
                            pe.dump_id > %s AND
                            pe.corrupt = 'f' GROUP BY pe.sha1) as a
                        JOIN
                        (SELECT p.sha1, trusted_av_labels, dump_id
                        FROM pe_dumps AS p JOIN
                            ped_vts_mapping as pvm USING (dump_id),
                            virus_total_scans as vts
                        WHERE pvm.vt_id = vts.vt_id AND
                            p.host LIKE %s AND
                            dump_id > %s AND
                            p.corrupt='f') as b
                        ON a.max_id = b.dump_id
                    WHERE trusted_av_labels IS NOT NULL""",
                           (twold, start_id, twold, start_id))
            if cursor.rowcount > 0:
                averages = cursor.fetchone()
                avg_trusted = averages[0]
                if avg_trusted is not None:
                    avg_trusted = float(avg_trusted)
                    self.twold_avg_trusted_labels[twold] = avg_trusted
                    s.update(twold, avg_trusted)

        return util.serialize_sketch('twold_avg_trusted_labels.p', s)

    def insert_twold_avg_av_labels_trusted_labels(self, s1, s2, window):
        """
        Insertion of feature twold_avg_av_labels and bgp avg_trusted_labels
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for twold in self.twold_list:

            cursor.execute("""SELECT AVG(num_av_labels), AVG(trusted_av_labels)
                    FROM
                        (SELECT pe.sha1, MAX(dump_id) AS max_id
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
                        ON a.max_id = b.dump_id
                    WHERE num_av_labels IS NOT NULL""",
                           (twold, start_id, twold, start_id))
            if cursor.rowcount > 0:
                averages = cursor.fetchone()
                avg_av = averages[0]
                avg_trusted = averages[1]
                if avg_av is not None:
                    avg_av = float(avg_av)
                    self.twold_avg_av_labels[twold] = avg_av
                    s1.update(twold, avg_av)
                if avg_trusted is not None:
                    avg_trusted = float(avg_trusted)
                    self.twold_avg_trusted_labels[twold] = avg_trusted
                    s2.update(twold, avg_trusted)

        return util.serialize_sketch('twold_avg_av_labels.p', s1), util.serialize_sketch('twold_avg_trusted_labels.p', s2)


    def get_twold_avg_av_labels_trusted_labels(self, s1, s2):
        """
        Retrieving of feature twold_avg_av_labels and twold avg_trusted_labels
        """
        print "\nTWOLD_AVG_AV_LABELS_TRUSTED_LABELS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_avg_av_labels.iteritems(), s1)

        print_results("2ld_avg_av_labels", "twold", temp_tot, error_list, total_error, max_error)

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_avg_trusted_labels.iteritems(), s2)

        print_results("2ld_avg_trusted_labels", "twold", temp_tot, error_list, total_error, max_error)

        return

    def insert_twold_unknown_hashes(self, s, window):
        """
        Insertion of feature twold_unknown_hashes
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for twold in self.twold_list:
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
            self.twold_unknown_hash[twold] = twold_unknown_hashes
            s.update(twold, twold_unknown_hashes)

        return util.serialize_sketch('twold_unknown_hash.p', s)

    def get_twold_unknown_hashes(self, s):
        """
        Retrieving of feature twold_unknown_hashes
        """
        print "\nTWOLD_UNKNOWN_HASHES:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_unknown_hash.iteritems(), s)

        print_results("2ld_unknown_hashes", "twold", temp_tot, error_list, total_error, max_error)

        return

    def insert_twold_total_hashes(self, s, window):
        """
        Insertion of feature twold_total_hashes
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        for twold in self.twold_list:
            cursor.execute("""
                    SELECT COUNT(DISTINCT pe.sha1)
                    FROM pe_dumps AS pe
                    WHERE pe.host LIKE %s AND
                        pe.corrupt = 'f' AND
                        pe.dump_id > %s """,
                           (twold, start_id))
            twold_total_hashes = cursor.fetchone()[0]
            self.twold_total_hash[twold] = twold_total_hashes
            s.update(twold, twold_total_hashes)

        return util.serialize_sketch('twold_total_hash.p', s)

    def get_twold_total_hashes(self, s):
        """
        Retrieving of feature twold_total_hashes
        """
        print "\nTWOLD_TOTAL_HASHES:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_total_hash.iteritems(), s)

        print_results("2ld_total_hashes", "twold", temp_tot, error_list, total_error, max_error)

        return

    def insert_twold_unknown_hash_ratio(self, s):
        """
        Insertion of feature twold_unknown_hash_ratio
        """
        for twold, twold_unknown_hashes in self.twold_unknown_hash.iteritems():
            twold_total_hashes = self.twold_total_hash[twold]
            ratio = float(twold_unknown_hashes / twold_total_hashes)
            self.twold_unknown_hash_ratio[twold] = ratio
            s.update(twold, ratio)

        return util.serialize_sketch('twold_unknown_hash_ratio.p', s)

    def get_twold_unknown_hash_ratio(self, s):
        """
        Retrieving of feature twold_unknown_hash_ratio
        """
        print "\nTWOLD_UNKNOWN_HASH_RATIO:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.twold_unknown_hash_ratio.iteritems(), s)

        print_results("2ld_unknown_hash_ratio", "twold", temp_tot, error_list, total_error, max_error)

        return

    # PAST FILE DOWNLOAD FEATURE EXTRACTION #

    def insert_hash_life_time(self, s, window):
        """
        Insertion of feature hash_life_time and min_dumps_same_hash
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""select distinct sha1 from pe_dumps where dump_id > %s""",
                       (start_id, ))

        for row in cursor:
            if row is not None:
                sha1 = row[0]
                if sha1 is None:
                    continue

                inner_cursor.execute("""
                    SELECT EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp)))
                    FROM pe_dumps AS pe
                    WHERE pe.dump_id > %s AND
                        pe.sha1 = %s AND
                        pe.corrupt = 'f' """,
                                     (start_id, sha1))
                hash_life_time = inner_cursor.fetchone()[0]

                if hash_life_time is not None:
                    self.hash_life_time[sha1] = hash_life_time
                    s.update(sha1, hash_life_time)

        return util.serialize_sketch('hash_life_time.p', s)

    def insert_min_dumps_same_hash(self, s, window):
        """
        Insertion of feature min_dumps_same_hash
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""select distinct sha1 from pe_dumps where dump_id > %s""",
                       (start_id, ))

        for row in cursor:
            if row is not None:
                sha1 = row[0]
                if sha1 is None:
                    continue

                inner_cursor.execute("""
                    SELECT COUNT(DISTINCT pe.dump_id)
                    FROM pe_dumps AS pe
                    WHERE pe.dump_id > %s AND
                        pe.sha1 = %s AND
                        pe.corrupt = 'f' """,
                                     (start_id, sha1))
                num_dumps_with_same_hash = inner_cursor.fetchone()[0]

                if num_dumps_with_same_hash is not None:
                    self.num_dumps_with_same_hash[sha1] = num_dumps_with_same_hash
                    s.update(sha1, num_dumps_with_same_hash)

        return util.serialize_sketch('num_dumps_with_same_hash.p', s)

    def insert_hash_life_time_min_dumps_same_hash(self, s1, s2, window):
        """
        Insertion of feature hash_life_time and min_dumps_same_hash
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""select distinct sha1 from pe_dumps where dump_id > %s""",
                       (start_id, ))

        for row in cursor:
            sha1 =row[0]
            if sha1 is None:
                continue

            inner_cursor.execute("""
                SELECT EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))),
                    COUNT(DISTINCT pe.dump_id)
                FROM pe_dumps AS pe
                WHERE pe.dump_id > %s AND
                    pe.sha1 = %s AND
                    pe.corrupt = 'f' """,
                                 (start_id, sha1))
            hash_life_time, num_dumps_with_same_hash = inner_cursor.fetchone()
            if (hash_life_time is None) and (num_dumps_with_same_hash is None):
                continue
            else:
                if hash_life_time is None:
                    self.num_dumps_with_same_hash[sha1] = num_dumps_with_same_hash
                    s2.update(sha1, num_dumps_with_same_hash)
                    continue
                else:
                    if num_dumps_with_same_hash is None:
                        self.hash_life_time[sha1] = hash_life_time
                        s1.update(sha1, hash_life_time)
                        continue

            self.hash_life_time[sha1] = hash_life_time
            self.num_dumps_with_same_hash[sha1] = num_dumps_with_same_hash

            s1.update(sha1, hash_life_time)
            s2.update(sha1, num_dumps_with_same_hash)

        return util.serialize_sketch('hash_life_time.p', s1), util.serialize_sketch('num_dumps_with_same_hash.p', s2)

    def get_hash_life_time_min_dumps_same_hash(self, s1, s2):
        """
        Retrieving of features hash_life_time and min_dumps_with_same_hash
        """
        print "\nHASH_LIFE_TIME_MIN_DUMPS_SAME_HASH:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.hash_life_time.iteritems(), s1)

        print_results("hash_life_time", "hash", temp_tot, error_list, total_error, max_error)

        temp_tot, error_list, total_error, max_error = compute_stats(self.num_dumps_with_same_hash.iteritems(), s2)

        print_results("num_dump_same_hash", "hash", temp_tot, error_list, total_error, max_error)

        return

    def insert_hash_daily_dump_rate(self, s, window):
        """
        Insertion of feature hash_daily_dump_rate_per_client
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""select distinct sha1 from pe_dumps where dump_id > %s""",
                       (start_id, ))

        for row in cursor:
            if row is not None:
                sha1 = row[0]
                if sha1 is None:
                    continue

                inner_cursor.execute("""
                            SELECT AVG(count)
                    FROM
                        (SELECT client,
                            date_trunc('day', timestamp) AS ts,
                            COUNT(*)
                        FROM pe_dumps AS pe
                        WHERE pe.dump_id > %s AND
                            pe.corrupt='f' AND
                            pe.sha1 = %s
                        GROUP BY client, ts) AS b""",
                                     (start_id, sha1))
                hash_daily_dump_rate_per_client = inner_cursor.fetchone()[0]
                if hash_daily_dump_rate_per_client is not None:
                    self.hash_daily_dump_rate[sha1] = float(hash_daily_dump_rate_per_client)
                    s.update(sha1, float(hash_daily_dump_rate_per_client))

        return util.serialize_sketch('hash_daily_dump_rate.p', s)

    def get_hash_daily_dump_rate(self, s):
        """
        Retrieving of feature hash_daily_dump_rate_per_client
        """
        print "\nHASH_DAILY_DUMP_RATE_PER_CLIENT:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.hash_daily_dump_rate.iteritems(), s)

        print_results("hash_daily_dump_rate_per_client", "hash", temp_tot, error_list, total_error, max_error)

        return

    def insert_estimated_clients_same_hash(self, s, window):
        """
        Insertion of feature estimated_clients_same_hash
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""select distinct sha1 from pe_dumps where dump_id > %s""",
                       (start_id, ))

        for row in cursor:
            if row is not None:
                sha1 = row[0]
                if sha1 is None:
                    continue

                inner_cursor.execute("""
                        SELECT count(*) FROM
                    (SELECT DISTINCT client,
                        DATE_TRUNC('DAY', timestamp)
                    FROM pe_dumps AS pe
                    WHERE pe.dump_id > %s AND
                        pe.corrupt='f' AND
                        pe.sha1 = %s) AS a""",
                                     (start_id, sha1))
            estimated_clients_with_same_hash = inner_cursor.fetchone()[0]
            if estimated_clients_with_same_hash is not None:
                self.estimated_clients_same_hash[sha1] = float(estimated_clients_with_same_hash)
                s.update(sha1, float(estimated_clients_with_same_hash))

        return util.serialize_sketch('estimated_clients_same_hash.p', s)

    def get_estimated_clients_with_same_hash(self, s):
        """
        Retrieving of feature estimated_clients_with_same_hash
        """
        print "\nESTIMATED_CLIENTS_WITH_SAME_HASH:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.estimated_clients_same_hash.iteritems(), s)

        print_results("estimated_clients_with_same_hash", "hash", temp_tot, error_list, total_error, max_error)

        return

    # URL FEATURES #
    def insert_url_malware_downloads(self, s, window):
        """
        Insertion of feature url_malware_downloads
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct url
            FROM pe_dumps AS pe
            WHERE
                pe.dump_id > %d and url is not null""" %
                       (start_id,))

        for row in cursor:
            if row is not None:
                url = row[0]
                inner_cursor.execute("""
                SELECT COUNT(DISTINCT dump_id)
                FROM pe_dumps AS pe JOIN
                    ped_vts_mapping AS pvm USING (dump_id),
                    virus_total_scans AS vts
                WHERE vts.trusted_av_labels > 1 AND
                    pe.url = %s AND
                    pe.dump_id > %s AND
                    pvm.vt_id = vts.vt_id """,
                                     (url, start_id))
                url_malware_downloads = inner_cursor.fetchone()[0]

                self.url_malware_downloads[url] = url_malware_downloads
                s.update(url, url_malware_downloads)

        return util.serialize_sketch('url_malware.p', s)

    def get_url_malware_downloads(self, s):
        """
        Retrieving of feature url_malware_downloads
        """
        print "\nURL_MALWARE_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.url_malware_downloads.iteritems(), s)

        print_results("url_malware_downloads", "url", temp_tot, error_list, total_error, max_error)

        return

    def insert_url_total_downloads(self, s, window):
        """
        Insertion of feature url_total_downloads

        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct url
            FROM pe_dumps AS pe
            WHERE
                pe.dump_id > %d and url is not null""" %
                       (start_id,))

        for row in cursor:
            if row is not None:
                url = row[0]
                inner_cursor.execute("""
                  SELECT COUNT(DISTINCT dump_id)
                    FROM pe_dumps AS pe
                    WHERE pe.url = %s AND
                        pe.dump_id > %s """,
                                     (url, start_id))
                url_total_downloads = inner_cursor.fetchone()[0]

                self.url_total_downloads[url] = url_total_downloads
                s.update(url, url_total_downloads)

        return util.serialize_sketch('url_total.p', s)

    def get_url_total_downloads(self, s):
        """
        Retrieving of feature url_total_downloads
        """
        print "\nURL_TOTAL_DOWNLOADS:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.url_total_downloads.iteritems(), s)

        print_results("url_total_downloads", "url", temp_tot, error_list, total_error, max_error)

        return

    def insert_url_distinct_sha1(self, s, window):
        """
        Insertion of feature url_distinct_sha1
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct url
            FROM pe_dumps AS pe
            WHERE
                pe.dump_id > %d and url is not null""" %
                       (start_id,))

        for row in cursor:
            if row is not None:
                url = row[0]
                inner_cursor.execute("""
                    SELECT COUNT(DISTINCT pe.sha1)
                    FROM pe_dumps AS pe
                    WHERE pe.url = %s AND
                        pe.dump_id > %s AND
                        pe.corrupt='f'""",
                                     (url, start_id))
                url_distinct_sha1 = inner_cursor.fetchone()[0]

                self.url_distinct_sha1s[url] = url_distinct_sha1
                s.update(url, url_distinct_sha1)

        return util.serialize_sketch('url_distinct_sha1s.p', s)

    def get_url_distinct_sha1(self, s):
        """
        Retrieving of feature url_distinct_sha1
        """
        print "\nURL_DISTINCT_SHA1:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.url_distinct_sha1s.iteritems(), s)

        print_results("url_distinct_sha1", "url", temp_tot, error_list, total_error, max_error)

        return

    def insert_url_struct_malware(self, s, window):
        """
        Insertion of feature url_struct
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct url
            FROM pe_dumps AS pe
            WHERE
                pe.dump_id > %d and url is not null """ %
                       (start_id,))

        for row in cursor:
            if row is not None:
                url = row[0]

                parsed_url = urlparse.urlparse(url)
                query = parsed_url.query

                m = re.search('([^\w]*)([\w]+)([^\w]+)(.*)', query)
                if m is None:
                    continue
                first_exp = m.group(1)
                divide = m.group(3)
                rest = m.group(4)
                url_struct = None
                if first_exp is not None:
                    url_struct = first_exp
                if rest is not None:
                    url_struct += "\w*" + divide
                while True:
                    m = re.search('([\w]+)([^\w]+)?(.*)', rest)
                    if m is not None:
                        divide = m.group(2)
                        rest = m.group(3)
                        if divide:
                            url_struct += "\w*" + divide
                        else:
                            url_struct += "\w*"
                    else:
                        break

                if len(url_struct) < 10:
                    continue
                pmd, ptd, pds = util.get_url_struct_matches(inner_cursor, url_struct, start_id)

                self.url_struct_malware_downloads[url] = pmd
                s.update(url, pmd)

        return util.serialize_sketch('url_struct_malware_downloads.p', s)

    def insert_url_struct_total(self, s, window):
        """
        Insertion of feature url_struct
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct url
            FROM pe_dumps AS pe
            WHERE
                pe.dump_id > %d and url is not null """ %
                       (start_id,))

        for row in cursor:
            if row is not None:
                url = row[0]

                parsed_url = urlparse.urlparse(url)
                query = parsed_url.query

                m = re.search('([^\w]*)([\w]+)([^\w]+)(.*)', query)
                if m is None:
                    continue
                first_exp = m.group(1)
                divide = m.group(3)
                rest = m.group(4)
                url_struct = None
                if first_exp is not None:
                    url_struct = first_exp
                if rest is not None:
                    url_struct += "\w*" + divide
                while True:
                    m = re.search('([\w]+)([^\w]+)?(.*)', rest)
                    if m is not None:
                        divide = m.group(2)
                        rest = m.group(3)
                        if divide:
                            url_struct += "\w*" + divide
                        else:
                            url_struct += "\w*"
                    else:
                        break

                if len(url_struct) < 10:
                    continue
                pmd, ptd, pds = util.get_url_struct_matches(inner_cursor, url_struct, start_id)

                self.url_struct_total_downloads[url] = ptd
                s.update(url, ptd)

        return util.serialize_sketch('url_struct_total_downloads.p', s)

    def insert_url_struct_distinct_sha1(self, s , window):
        """
        Insertion of feature url_struct
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct url
            FROM pe_dumps AS pe
            WHERE
                pe.dump_id > %d and url is not null """ %
                       (start_id,))

        for row in cursor:
            if row is not None:
                url = row[0]

                parsed_url = urlparse.urlparse(url)
                query = parsed_url.query

                m = re.search('([^\w]*)([\w]+)([^\w]+)(.*)', query)
                if m is None:
                    continue
                first_exp = m.group(1)
                divide = m.group(3)
                rest = m.group(4)
                url_struct = None
                if first_exp is not None:
                    url_struct = first_exp
                if rest is not None:
                    url_struct += "\w*" + divide
                while True:
                    m = re.search('([\w]+)([^\w]+)?(.*)', rest)
                    if m is not None:
                        divide = m.group(2)
                        rest = m.group(3)
                        if divide:
                            url_struct += "\w*" + divide
                        else:
                            url_struct += "\w*"
                    else:
                        break

                if len(url_struct) < 10:
                    continue
                pmd, ptd, pds = util.get_url_struct_matches(inner_cursor, url_struct, start_id)

                self.url_struct_distinct_sha1s[url] = pds
                s.update(url, pds)

        return util.serialize_sketch('url_struct_distinct_sha1s.p', s)

    def insert_url_struct_features(self, s1, s2, s3, window):
        """
        Insertion of feature url_struct
        """
        conn = util.connect_to_db()
        cursor = conn.cursor()
        inner_cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct url
            FROM pe_dumps AS pe
            WHERE
                pe.dump_id > %d and url is not null """ %
                       (start_id,))

        for row in cursor:
            if row is not None:
                url = row[0]

                parsed_url = urlparse.urlparse(url)
                query = parsed_url.query

                m = re.search('([^\w]*)([\w]+)([^\w]+)(.*)', query)
                if m is None:
                    continue
                first_exp = m.group(1)
                divide = m.group(3)
                rest = m.group(4)
                url_struct = None
                if first_exp is not None:
                    url_struct = first_exp
                if rest is not None:
                    url_struct += "\w*" + divide
                while True:
                    m = re.search('([\w]+)([^\w]+)?(.*)', rest)
                    if m is not None:
                        divide = m.group(2)
                        rest = m.group(3)
                        if divide:
                            url_struct += "\w*" + divide
                        else:
                            url_struct += "\w*"
                    else:
                        break

                if len(url_struct) < 10:
                    continue
                pmd, ptd, pds = util.get_url_struct_matches(inner_cursor, url_struct, start_id)

                self.url_struct_malware_downloads[url] = pmd
                s1.update(url, pmd)
                self.url_struct_total_downloads[url] = ptd
                s2.update(url, ptd)
                self.url_struct_distinct_sha1s[url] = pds
                s3.update(url, pds)

        return util.serialize_sketch('url_struct_malware_downloads.p', s1), \
               util.serialize_sketch('url_struct_total_downloads.p', s2), \
               util.serialize_sketch('url_struct_distinct_sha1.p', s3)

    def get_url_struct_features(self, s1, s2, s3):
        """
        Retrieving of feature url_struct
        """
        print "\nURL_STRUCT:\n"

        temp_tot, error_list, total_error, max_error = compute_stats(self.url_struct_malware_downloads.iteritems(), s1)

        print_results("url_struct_malware_downloads", "url", temp_tot, error_list, total_error, max_error)

        temp_tot, error_list, total_error, max_error = compute_stats(self.url_struct_total_downloads.iteritems(), s2)

        print_results("url_struct_total_downloads", "url", temp_tot, error_list, total_error, max_error)

        temp_tot, error_list, total_error, max_error = compute_stats(self.url_struct_distinct_sha1s.iteritems(), s3)

        print_results("url_struct_distinct_sha1", "url", temp_tot, error_list, total_error, max_error)

        return

    def get_twold_mapping(self, window):

        conn = util.connect_to_db()
        cursor = conn.cursor()

        start_id = self.maxID - window

        cursor.execute("""SELECT distinct host
                        FROM pe_dumps
                        WHERE dump_id > %d
                        and host is not null and corrupt = 'f'""" %
                       (start_id,))

        for row in cursor:
            if row is not None and row[0]:
                host = row[0]
                try:
                    key = util.reorder_domain(row[0])
                    twold = util.extract_twold(key)
                    twold = util.reorder_domain(twold)
                    twold += '%'
                except Exception as e:
                    if util.is_ip(host):
                        twold = row[0]
                    else:
                        print "Error in extracting 2LD!, ", e, host
                        continue
                self.host_twold_mapping[host] = twold

                if twold not in self.twold_list:
                    self.twold_list.append(twold)

        print "twold mapping computed!"
        output = open("./host_twold_mapping", 'wb')
        pickle.dump(self.host_twold_mapping, output)
        output.close()

        output = open("./twold_list", 'wb')
        pickle.dump(self.twold_list, output)
        output.close()

        return

    def get_twold_mapping_from_sketch(self):

        self.host_twold_mapping = pickle.load(open("./host_twold_mapping",'rb'))
        self.twold_list = pickle.load(open("./twold_list",'rb'))

        return


# noinspection PyStringFormat
def print_results(name, directory, temp_tot, error_list, total_error, max_error):
    mean_value = temp_tot / error_list.size
    avg_error = np.mean(error_list)
    variance = np.var(error_list)
    std_deviation = np.std(error_list)
    error_rate = avg_error / mean_value * 100
    variance_rate = variance / mean_value * 100

    print "Total number of elements: %d" % error_list.size
    print "Total error in feature %s: %f" % (name, total_error)
    print "Maximum error in feature %s: %f" % (name, max_error)
    print "Average error in feature %s: %f" % (name, avg_error)
    print "Variance in feature %s: %f " % (name, variance)
    print "Standard deviation in feature %s: %f" % (name, std_deviation)
    print "Mean value in feature %s: %f" % (name, mean_value)
    print "Error rate in feature %s: %f" % (name, error_rate)
    print "Variance rate in feature %s: %f" % (name, variance_rate)

    filename = name.upper()

    util.log(filename, directory, error_list.size, total_error, max_error,
             avg_error, variance, std_deviation, mean_value, error_rate, variance_rate)
    return

def compute_stats(iterator, s):
    total_error = 0.0
    max_error = 0.0

    temp_tot = 0.0

    error_list = np.array([])

    for key, db_count in iterator:
        count_min_val = s.get(key)

        temp_tot += db_count

        difference = count_min_val - db_count
        if difference > max_error:
            max_error = difference
        if difference < 0:
            raise ValueError("Error: sketch counter lower than real value")

        error_list = np.append(error_list, difference)

        total_error += difference

    return temp_tot, error_list, total_error, max_error