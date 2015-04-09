__author__ = 'vincenzo'

from sketch import Sketch

import urlparse
import re
import psycopg2
import util
import sys

debug = 0 #Used to control if the sketches created with no errors return the same results as amico_db

MAX_PAST_DUMPS = 30000
def insert_host_based_features(cursor, dump_id, min_id):

    cursor.execute("""
        SELECT host FROM pe_dumps
        WHERE dump_id = %s""",
        (dump_id, ))
    row = cursor.fetchone()
    if row is not None:
        host = row[0]
    else:
        return

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe
        WHERE pe.host = %s AND
            pe.dump_id > %s """,
        (host, min_id))
    host_total_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('host_total.p')

    host_total_downloads_sketch = int(sketch.get(host))

    if debug == 1 and host_total_downloads != host_total_downloads_sketch:
        print "host_total_downloads: ", host_total_downloads
        print "host_total_downloads_sketch: ", host_total_downloads_sketch
        raise Exception("Amico db - sketch mapping error")

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.num_av_labels = 0 AND
            pe.host = %s AND
            pe.dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
        (host, min_id))
    host_benign_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('host_benign.p')

    host_benign_downloads_sketch = int(sketch.get(host))

    if debug == 1 and host_benign_downloads != host_benign_downloads_sketch:
        print "host_benign_downloads: ", host_benign_downloads
        print "host_benign_downloads_sketch: ", host_benign_downloads_sketch
        raise Exception("Amico db - sketch mapping error")

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.trusted_av_labels > 1 AND
            pe.host = %s AND
            dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
        (host, min_id))
    host_malware_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('host_malware.p')

    host_malware_downloads_sketch = int(sketch.get(host))

    if debug == 1 and host_malware_downloads != host_malware_downloads_sketch:
        print "host_malware_downloads: ", host_malware_downloads
        print "host_malware_downloads_sketch: ", host_malware_downloads_sketch
        raise Exception("Amico db - sketch mapping error")

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.num_av_labels > 1 AND
            pe.host = %s AND
            pe.dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
        (host, min_id))
    host_suspicious_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('host_suspicious.p')

    host_suspicious_downloads_sketch = int(sketch.get(host))

    if debug == 1 and host_suspicious_downloads != host_suspicious_downloads_sketch:
        print "host_suspicious_downloads: ", host_suspicious_downloads
        print "host_suspicious_downloads_sketch: ", host_suspicious_downloads_sketch
        raise Exception("Amico db - sketch mapping error")

    if host_total_downloads == 0:
        host_benign_ratio = 0
        host_malware_ratio = 0
        host_suspicious_ratio = 0
    else:
        host_benign_ratio = float(host_benign_downloads) / host_total_downloads
        host_malware_ratio = float(host_malware_downloads) / host_total_downloads
        host_suspicious_ratio = float(host_suspicious_downloads) / host_total_downloads

    if host_total_downloads_sketch == 0:
        host_benign_ratio_sketch = 0
        host_malware_ratio_sketch = 0
        host_suspicious_ratio_sketch = 0
    else:
        sketch = util.deserialize_sketch('host_malware_ratio.p')
        host_malware_ratio_sketch = float(sketch.get(host))
        sketch = util.deserialize_sketch('host_benign_ratio.p')
        host_benign_ratio_sketch = float(sketch.get(host))
        sketch = util.deserialize_sketch('host_suspicious_ratio.p')
        host_suspicious_ratio_sketch = float(sketch.get(host))

    if debug == 1 and host_benign_ratio != host_benign_ratio_sketch:
        print "host_benign_ratio: ", host_benign_ratio
        print "host_benign_ratio_sketch: ", host_benign_ratio_sketch
        raise Exception("Amico db - sketch mapping error")

    if debug == 1 and host_malware_ratio != host_malware_ratio_sketch:
        print "host_malware_ratio: ", host_malware_ratio
        print "host_malware_ratio_sketch: ", host_malware_ratio_sketch
        raise Exception("Amico db - sketch mapping error")

    # The averages are over distinct sha1s
    cursor.execute("""
        SELECT AVG(num_av_labels), AVG(trusted_av_labels)
        FROM
            (SELECT pe.sha1, MAX(dump_id) AS max_id
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
            ON a.max_id = b.dump_id
        WHERE num_av_labels IS NOT NULL""",
    (host, min_id, host, min_id))
    if cursor.rowcount == 0:
        host_avg_av_labels = 0
        host_avg_trusted_labels = 0
        host_avg_av_labels_sketch = 0
        host_avg_trusted_labels_sketch = 0
    else:
        host_avg_av_labels, host_avg_trusted_labels = cursor.fetchone()

        sketch = util.deserialize_sketch('host_avg_av_labels.p')
        host_avg_av_labels_sketch = float(sketch.get(host))
        sketch = util.deserialize_sketch('host_avg_trusted_labels.p')
        host_avg_trusted_labels_sketch = float(sketch.get(host))

        if(host_avg_av_labels is None):
            host_avg_av_labels_sketch = None
        if(host_avg_trusted_labels is None):
            host_avg_trusted_labels_sketch = None

    # the oldest scan report is used to get the # of unknown hashes
    # to remove any bias due to VT submissions
    cursor.execute("""
        SELECT COUNT(DISTINCT b.sha1)
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
    (host, min_id, host, min_id))
    host_unknown_hashes = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('host_unknown_hash.p')
    host_unknown_hashes_sketch = int(sketch.get(host))

    cursor.execute("""
        SELECT COUNT(DISTINCT pe.sha1)
        FROM pe_dumps AS pe
        WHERE pe.host = %s AND
            pe.corrupt = 'f' AND
            pe.dump_id > %s """,
        (host, min_id))
    host_total_hashes = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('host_total_hash.p')
    host_total_hashes_sketch = int(sketch.get(host))

    if host_total_hashes != 0:
        host_unknown_hash_ratio = float(host_unknown_hashes) / host_total_hashes
    else:
        host_unknown_hash_ratio = 0

    sketch = util.deserialize_sketch('host_unknown_hash_ratio.p')
    host_unknown_hash_ratio_sketch = sketch.get(host)

    try:
        cursor.execute("""
                UPDATE weka_features set host_benign_downloads = %s,
                 host_malware_downloads = %s,
                 host_suspicious_downloads = %s,
                 host_total_downloads = %s,
                 host_malware_ratio = %s,
                 host_suspicious_ratio = %s,
                 host_benign_ratio = %s,
                 host_avg_av_labels = %s,
                 host_avg_trusted_labels = %s,
                 host_unknown_hashes = %s,
                 host_total_hashes = %s,
                 host_unknown_hash_ratio = %s
                 where dump_id = %s """,
                (host_benign_downloads, host_malware_downloads,
                 host_suspicious_downloads,
                 host_total_downloads, host_malware_ratio,
                 host_suspicious_ratio,
                 host_benign_ratio,
                 host_avg_av_labels, host_avg_trusted_labels,
                 host_unknown_hashes, host_total_hashes,
                 host_unknown_hash_ratio, dump_id))

        cursor.execute("""
                UPDATE weka_features_sketch set host_benign_downloads = %s,
                 host_malware_downloads = %s,
                 host_suspicious_downloads = %s,
                 host_total_downloads = %s,
                 host_malware_ratio = %s,
                 host_suspicious_ratio = %s,
                 host_benign_ratio = %s,
                 host_avg_av_labels = %s,
                 host_avg_trusted_labels = %s,
                 host_unknown_hashes = %s,
                 host_total_hashes = %s,
                 host_unknown_hash_ratio = %s
                 where dump_id = %s """,
                (host_benign_downloads_sketch, host_malware_downloads_sketch,
                 host_suspicious_downloads_sketch,
                 host_total_downloads_sketch, host_malware_ratio_sketch,
                 host_suspicious_ratio_sketch,
                 host_benign_ratio_sketch,
                 host_avg_av_labels_sketch, host_avg_trusted_labels_sketch,
                 host_unknown_hashes_sketch, host_total_hashes_sketch,
                 host_unknown_hash_ratio_sketch, dump_id))

    except Exception as e:
        print e
        print "Could not insert host based features for the dump #", dump_id

def insert_twold_based_features(cursor, dump_id, min_id):
    cursor.execute("""
           SELECT host FROM pe_dumps where
           dump_id = %s""", (dump_id, ))
    row = cursor.fetchone()
    try:
        # ok because AND clauses are evaluated left to right
        if row is not None and row[0]:
            host = util.reorder_domain(row[0])
            twold = util.extract_twold(host)
            twold = util.reorder_domain(twold)
            twold += '%'
        else:
            print "host is None!"
            return
    except Exception as e:
        # capturing known causes
        if util.is_ip(host):
            twold = row[0]
        else:
            print "Error in extracting 2LD!, ", e, host, dump_id
            return

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe
        WHERE pe.host LIKE %s AND
            pe.dump_id > %s""",
        (twold, min_id))
    twold_total_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('twold_total.p')
    twold_total_downloads_sketch = int(sketch.get(twold))

    # Disabled vt_month_shelf due to the 403 error from VT
    #cursor.execute("""
    #    SELECT count(distinct dump_id) from pe_dumps as pe JOIN
    #    weka_features as f using (dump_id)
    #    where f.raw_dump_num_av_labels = 0 and f.vt_month_shelf = 't' and
    #    pe.host like %s and pe.dump_id < %s """,
    #    (twold, dump_id))
    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.num_av_labels = 0 AND
            pe.host LIKE %s AND
            pe.dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
        (twold, min_id))
    twold_benign_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('twold_benign.p')
    twold_benign_downloads_sketch = int(sketch.get(twold))

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.trusted_av_labels > 1 AND
            pe.host LIKE %s AND
            pe.dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
        (twold, min_id))
    twold_malware_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('twold_malware.p')
    twold_malware_downloads_sketch = int(sketch.get(twold))

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.num_av_labels > 1 AND
            pe.host LIKE %s AND
            pe.dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
        (twold, min_id))
    twold_suspicious_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('twold_suspicious.p')
    twold_suspicious_downloads_sketch = int(sketch.get(twold))

    if twold_total_downloads == 0:
        twold_benign_ratio = 0
        twold_malware_ratio = 0
        twold_suspicious_ratio = 0
    else:
        twold_benign_ratio = float(twold_benign_downloads) / twold_total_downloads
        twold_malware_ratio = float(twold_malware_downloads) / twold_total_downloads
        twold_suspicious_ratio = float(twold_suspicious_downloads) / twold_total_downloads

    if twold_total_downloads_sketch == 0:
        twold_benign_ratio_sketch = 0
        twold_malware_ratio_sketch = 0
        twold_suspicious_ratio_sketch = 0
    else:
        sketch = util.deserialize_sketch('twold_benign_ratio.p')
        twold_benign_ratio_sketch = float(sketch.get(twold))
        sketch = util.deserialize_sketch('twold_malware_ratio.p')
        twold_malware_ratio_sketch = float(sketch.get(twold))
        sketch = util.deserialize_sketch('twold_suspicious_ratio.p')
        twold_suspicious_ratio_sketch = float(sketch.get(twold))

    # The averages are over distinct sha1s
    cursor.execute("""
        SELECT AVG(num_av_labels), AVG(trusted_av_labels)
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
        (twold, min_id, twold, min_id))
    if cursor.rowcount == 0:
        twold_avg_av_labels = 0
        twold_avg_trusted_labels = 0
        twold_avg_av_labels_sketch = 0
        twold_avg_trusted_labels_sketch = 0
    else:
        twold_avg_av_labels, twold_avg_trusted_labels = cursor.fetchone()

        sketch = util.deserialize_sketch('twold_avg_av_labels.p')
        twold_avg_av_labels_sketch = float(sketch.get(twold))
        sketch = util.deserialize_sketch('twold_avg_trusted_labels.p')
        twold_avg_trusted_labels_sketch = float(sketch.get(twold))

        if(twold_avg_av_labels is None):
            twold_avg_av_labels_sketch = None
        if(twold_avg_trusted_labels is None):
            twold_avg_trusted_labels_sketch = None

    # the oldest scan report is used to get the # of unknown hashes
    # to remove any bias due to VT submissions
    cursor.execute("""
        SELECT COUNT(DISTINCT b.sha1)
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
        (twold, min_id, twold, min_id))
    twold_unknown_hashes = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('twold_unknown_hash.p')
    twold_unknown_hashes_sketch = int(sketch.get(twold))

    cursor.execute("""
        SELECT COUNT(DISTINCT pe.sha1)
        FROM pe_dumps AS pe
        WHERE pe.host LIKE %s AND
            pe.corrupt = 'f' AND
            pe.dump_id > %s """,
        (twold, min_id))
    twold_total_hashes = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('twold_total_hash.p')
    twold_total_hashes_sketch = int(sketch.get(twold))

    if twold_total_hashes != 0:
        twold_unknown_hash_ratio = float(twold_unknown_hashes) / twold_total_hashes
    else:
        twold_unknown_hash_ratio = 0

    if twold_total_hashes_sketch != 0:
        sketch = util.deserialize_sketch('twold_unknown_hash_ratio.p')
        twold_unknown_hash_ratio_sketch = float(sketch.get(twold))
    else:
        twold_unknown_hash_ratio_sketch = 0

    try:
        cursor.execute("""
                UPDATE weka_features set twold_benign_downloads = %s,
                 twold_malware_downloads = %s,
                 twold_suspicious_downloads = %s,
                 twold_total_downloads = %s,
                 twold_malware_ratio = %s,
                 twold_suspicious_ratio = %s,
                 twold_benign_ratio = %s,
                 twold_avg_av_labels = %s,
                 twold_avg_trusted_labels = %s,
                 twold_unknown_hashes = %s,
                 twold_total_hashes = %s,
                 twold_unknown_hash_ratio = %s
                 where dump_id = %s """,
                (twold_benign_downloads, twold_malware_downloads,
                 twold_suspicious_downloads,
                 twold_total_downloads, twold_malware_ratio,
                 twold_suspicious_ratio,
                 twold_benign_ratio,
                 twold_avg_av_labels, twold_avg_trusted_labels,
                 twold_unknown_hashes, twold_total_hashes,
                 twold_unknown_hash_ratio, dump_id))

        cursor.execute("""
                UPDATE weka_features_sketch set twold_benign_downloads = %s,
                 twold_malware_downloads = %s,
                 twold_suspicious_downloads = %s,
                 twold_total_downloads = %s,
                 twold_malware_ratio = %s,
                 twold_suspicious_ratio = %s,
                 twold_benign_ratio = %s,
                 twold_avg_av_labels = %s,
                 twold_avg_trusted_labels = %s,
                 twold_unknown_hashes = %s,
                 twold_total_hashes = %s,
                 twold_unknown_hash_ratio = %s
                 where dump_id = %s """,
                (twold_benign_downloads_sketch, twold_malware_downloads_sketch,
                 twold_suspicious_downloads_sketch,
                 twold_total_downloads_sketch, twold_malware_ratio_sketch,
                 twold_suspicious_ratio_sketch,
                 twold_benign_ratio_sketch,
                 twold_avg_av_labels_sketch, twold_avg_trusted_labels_sketch,
                 twold_unknown_hashes_sketch, twold_total_hashes_sketch,
                 twold_unknown_hash_ratio_sketch, dump_id))
    except Exception as e:
        print e
        print "Could not insert twold based features for the dump #", dump_id

def insert_server_ip_based_features(cursor, dump_id, min_id):
    cursor.execute("""
            SELECT server from pe_dumps where dump_id = %s""", (dump_id, ))
    row = cursor.fetchone()
    if row is not None:
        server_ip = row[0]
    else:
        return

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe
        WHERE pe.server = %s AND
           pe.dump_id > %s """,
        (server_ip, min_id))
    server_ip_total_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('server_total.p')
    server_ip_total_downloads_sketch = int(sketch.get(server_ip))

    #print "server_ip_total_downloads:", server_ip_total_downloads

    # Disabled vt_month_shelf due to the 403 error from VT
    #cursor.execute("""
    #    SELECT count(distinct dump_id) from pe_dumps as pe JOIN
    #    weka_features as f using (dump_id)
    #    where f.raw_dump_num_av_labels = 0 and f.vt_month_shelf = 't' and
    #    pe.server = %s and pe.dump_id < %s """,
    #    (server_ip, dump_id))
    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.num_av_labels = 0 AND
            pe.server = %s AND
            pe.dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
        (server_ip, min_id))
    server_ip_benign_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('server_benign.p')
    server_ip_benign_downloads_sketch = int(sketch.get(server_ip))

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.trusted_av_labels > 1 AND
            pe.server = %s AND
            pe.dump_id >  %s AND
            vts.vt_id = pvm.vt_id""",
        (server_ip, min_id))
    server_ip_malware_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('server_malware.p')
    server_ip_malware_downloads_sketch = int(sketch.get(server_ip))

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.num_av_labels > 1 AND
            pe.server = %s AND
            pe.dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
        (server_ip, min_id))
    server_ip_suspicious_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('server_suspicious.p')
    server_ip_suspicious_downloads_sketch = int(sketch.get(server_ip))

    if server_ip_total_downloads == 0:
        server_ip_benign_ratio = None
        server_ip_malware_ratio = None
        server_ip_suspicious_ratio = None
    else:
        server_ip_benign_ratio = float(server_ip_benign_downloads) / server_ip_total_downloads
        server_ip_malware_ratio = float(server_ip_malware_downloads) / server_ip_total_downloads
        server_ip_suspicious_ratio = float(server_ip_suspicious_downloads) / server_ip_total_downloads

    if server_ip_total_downloads_sketch == 0:
        server_ip_benign_ratio_sketch = None
        server_ip_malware_ratio_sketch = None
        server_ip_suspicious_ratio_sketch = None
    else:
        sketch = util.deserialize_sketch('server_benign_ratio.p')
        server_ip_benign_ratio_sketch = float(sketch.get(server_ip))
        sketch = util.deserialize_sketch('server_malware_ratio.p')
        server_ip_malware_ratio_sketch = float(sketch.get(server_ip))
        sketch = util.deserialize_sketch('server_suspicious_ratio.p')
        server_ip_suspicious_ratio_sketch = float(sketch.get(server_ip))

    # The averages are over distinct sha1s
    cursor.execute("""
        SELECT AVG(num_av_labels), AVG(trusted_av_labels)
        FROM
            (SELECT pe.sha1, MAX(dump_id) AS max_id
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
                p.dump_id > %s AND
                p.corrupt='f') as b
            ON a.max_id = b.dump_id
        WHERE num_av_labels IS NOT NULL""",
    (server_ip, min_id, server_ip, min_id))
    if cursor.rowcount == 0:
        server_ip_avg_av_labels = None
        server_ip_avg_trusted_labels = None
        server_ip_avg_av_labels_sketch = None
        server_ip_avg_trusted_labels_sketch = None
    else:
        server_ip_avg_av_labels, server_ip_avg_trusted_labels = cursor.fetchone()

        sketch = util.deserialize_sketch('server_avg_av_labels.p')
        server_ip_avg_av_labels_sketch = float(sketch.get(server_ip))
        sketch = util.deserialize_sketch('server_avg_trusted_labels.p')
        server_ip_avg_trusted_labels_sketch = float(sketch.get(server_ip))

        if(server_ip_avg_av_labels is None):
            server_ip_avg_av_labels_sketch = None
        if(server_ip_avg_trusted_labels is None):
            server_ip_avg_trusted_labels_sketch = None

    # the oldest scan report is used to get the # of unknown hashes
    # to remove any bias due to VT submissions
    cursor.execute("""
        SELECT COUNT(DISTINCT b.sha1)
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
    (server_ip, min_id, server_ip, min_id))
    server_ip_unknown_hashes = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('server_unknown_hashes.p')
    server_ip_unknown_hashes_sketch = int(sketch.get(server_ip))

    cursor.execute("""
        SELECT COUNT(DISTINCT pe.sha1)
        FROM pe_dumps AS pe
        WHERE pe.server = %s AND
            pe.corrupt = 'f' AND
            pe.dump_id > %s """,
    (server_ip, min_id))
    server_ip_total_hashes = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('server_total_hashes.p')
    server_ip_total_hashes_sketch = int(sketch.get(server_ip))

    if server_ip_total_hashes != 0:
        server_ip_unknown_hash_ratio = float(server_ip_unknown_hashes) / server_ip_total_hashes
    else:
        server_ip_unknown_hash_ratio = None

    if server_ip_total_hashes_sketch != 0:
        sketch = util.deserialize_sketch('server_unknown_hash_ratio.p')
        server_ip_unknown_hash_ratio_sketch = float(sketch.get(server_ip))
    else:
        server_ip_unknown_hash_ratio_sketch = None

    try:
        cursor.execute("""
                UPDATE weka_features set server_ip_benign_downloads = %s,
                 server_ip_malware_downloads = %s,
                 server_ip_suspicious_downloads = %s,
                 server_ip_total_downloads = %s,
                 server_ip_malware_ratio = %s,
                 server_ip_suspicious_ratio = %s,
                 server_ip_benign_ratio = %s,
                 server_ip_avg_av_labels = %s,
                 server_ip_avg_trusted_labels = %s,
                 server_ip_unknown_hashes = %s,
                 server_ip_total_hashes = %s,
                 server_ip_unknown_hash_ratio = %s
                 where dump_id = %s """,
                (server_ip_benign_downloads, server_ip_malware_downloads,
                 server_ip_suspicious_downloads,
                 server_ip_total_downloads, server_ip_malware_ratio,
                 server_ip_suspicious_ratio,
                 server_ip_benign_ratio,
                 server_ip_avg_av_labels, server_ip_avg_trusted_labels,
                 server_ip_unknown_hashes, server_ip_total_hashes,
                 server_ip_unknown_hash_ratio, dump_id))

        cursor.execute("""
                UPDATE weka_features_sketch set server_ip_benign_downloads = %s,
                 server_ip_malware_downloads = %s,
                 server_ip_suspicious_downloads = %s,
                 server_ip_total_downloads = %s,
                 server_ip_malware_ratio = %s,
                 server_ip_suspicious_ratio = %s,
                 server_ip_benign_ratio = %s,
                 server_ip_avg_av_labels = %s,
                 server_ip_avg_trusted_labels = %s,
                 server_ip_unknown_hashes = %s,
                 server_ip_total_hashes = %s,
                 server_ip_unknown_hash_ratio = %s
                 where dump_id = %s """,
                (server_ip_benign_downloads_sketch, server_ip_malware_downloads_sketch,
                 server_ip_suspicious_downloads_sketch,
                 server_ip_total_downloads_sketch, server_ip_malware_ratio_sketch,
                 server_ip_suspicious_ratio_sketch,
                 server_ip_benign_ratio_sketch,
                 server_ip_avg_av_labels_sketch, server_ip_avg_trusted_labels_sketch,
                 server_ip_unknown_hashes_sketch, server_ip_total_hashes_sketch,
                 server_ip_unknown_hash_ratio_sketch, dump_id))

    except Exception as e:
        print e
        print "Could not insert server_ip based features for the dump #", dump_id

def insert_bgp_based_features(cursor, dump_id, min_id):

    cursor.execute("""
            SELECT server from pe_dumps where dump_id = %s""", (dump_id, ))
    server = cursor.fetchone()[0]

    cursor.execute("""
                    select bgp_prefix from bgp2asn where bgp_prefix >> %s""", (server,))
    row = cursor.fetchone()
    if row is not None:
        bgp_prefix = row[0]
    else:
        return

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe
        WHERE pe.server << %s AND
            pe.dump_id > %s """,
        (bgp_prefix, min_id))
    bgp_total_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('bgp_total.p')
    bgp_total_downloads_sketch = int(sketch.get(bgp_prefix))

    # Disabled vt_month_shelf due to the 403 error from VT
    #cursor.execute("""
    #    SELECT count(distinct dump_id) from pe_dumps as pe JOIN
    #    weka_features as f using (dump_id)
    #    where f.raw_dump_num_av_labels = 0 and f.vt_month_shelf = 't' and
    #    pe.server << %s and pe.dump_id < %s """,
    #    (bgp_prefix, dump_id))
    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.num_av_labels = 0 AND
            pe.server << %s AND
            pe.dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
        (bgp_prefix, min_id))
    bgp_benign_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('bgp_benign.p')
    bgp_benign_downloads_sketch = int(sketch.get(bgp_prefix))

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.trusted_av_labels > 1 AND
            pe.server << %s AND
            pe.dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
        (bgp_prefix, min_id))
    bgp_malware_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('bgp_malware.p')
    bgp_malware_downloads_sketch = int(sketch.get(bgp_prefix))

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.num_av_labels > 1 AND
            pe.server << %s AND
            pe.dump_id > %s AND
            vts.vt_id = pvm.vt_id""",
        (bgp_prefix, min_id))
    bgp_suspicious_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('bgp_suspicious.p')
    bgp_suspicious_downloads_sketch = int(sketch.get(bgp_prefix))

    if bgp_total_downloads == 0:
        bgp_benign_ratio = None
        bgp_malware_ratio = None
        bgp_suspicious_ratio = None
    else:
        bgp_benign_ratio = float(bgp_benign_downloads) / bgp_total_downloads
        bgp_malware_ratio = float(bgp_malware_downloads) / bgp_total_downloads
        bgp_suspicious_ratio = float(bgp_suspicious_downloads) / bgp_total_downloads

    if bgp_total_downloads_sketch == 0:
        bgp_benign_ratio_sketch = None
        bgp_malware_ratio_sketch = None
        bgp_suspicious_ratio_sketch = None
    else:
        sketch = util.deserialize_sketch('bgp_benign_ratio.p')
        bgp_benign_ratio_sketch = float(sketch.get(bgp_prefix))
        sketch = util.deserialize_sketch('bgp_malware_ratio.p')
        bgp_malware_ratio_sketch = float(sketch.get(bgp_prefix))
        sketch = util.deserialize_sketch('bgp_suspicious_ratio.p')
        bgp_suspicious_ratio_sketch = float(sketch.get(bgp_prefix))

    # The averages are over distinct sha1s
    cursor.execute("""
        SELECT AVG(num_av_labels), AVG(trusted_av_labels)
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
    (bgp_prefix, min_id, bgp_prefix, min_id))
    if cursor.rowcount == 0:
        bgp_avg_av_labels = None
        bgp_avg_trusted_labels = None
        bgp_avg_av_labels_sketch = None
        bgp_avg_trusted_labels_sketch = None
    else:
        bgp_avg_av_labels, bgp_avg_trusted_labels = cursor.fetchone()

        sketch = util.deserialize_sketch('bgp_avg_av_labels.p')
        bgp_avg_av_labels_sketch = float(sketch.get(bgp_prefix))
        sketch = util.deserialize_sketch('bgp_avg_trusted_labels.p')
        bgp_avg_trusted_labels_sketch = float(sketch.get(bgp_prefix))

        if(bgp_avg_av_labels is None):
            bgp_avg_av_labels_sketch = None
        if(bgp_avg_trusted_labels is None):
            bgp_avg_trusted_labels_sketch = None


    # the oldest scan report is used to get the # of unknown hashes
    # to remove any bias due to VT submissions
    cursor.execute("""
        SELECT COUNT(DISTINCT b.sha1)
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
    (bgp_prefix, min_id, bgp_prefix, min_id))
    bgp_unknown_hashes = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('bgp_unknown_hashes.p')
    bgp_unknown_hashes_sketch = int(sketch.get(bgp_prefix))

    cursor.execute("""
        SELECT COUNT(DISTINCT pe.sha1)
        FROM pe_dumps AS pe
        WHERE pe.server << %s AND
            pe.corrupt = 'f' AND
            pe.dump_id > %s """,
    (bgp_prefix, min_id))
    bgp_total_hashes = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('bgp_total_hash.p')
    bgp_total_hashes_sketch = int(sketch.get(bgp_prefix))
    if bgp_total_hashes != 0:
        bgp_unknown_hash_ratio = float(bgp_unknown_hashes) / bgp_total_hashes
    else:
        bgp_unknown_hash_ratio = None

    if bgp_total_hashes_sketch != 0:
        sketch = util.deserialize_sketch('bgp_unknown_hash_ratio.p')
        bgp_unknown_hash_ratio_sketch = float(sketch.get(bgp_prefix))
    else:
        bgp_unknown_hash_ratio_sketch = None

    try:
        cursor.execute("""
                UPDATE weka_features set bgp_benign_downloads = %s,
                 bgp_malware_downloads = %s,
                 bgp_suspicious_downloads = %s,
                 bgp_total_downloads = %s,
                 bgp_malware_ratio = %s,
                 bgp_suspicious_ratio = %s,
                 bgp_benign_ratio = %s,
                 bgp_avg_av_labels = %s,
                 bgp_avg_trusted_labels = %s,
                 bgp_unknown_hashes = %s,
                 bgp_total_hashes = %s,
                 bgp_unknown_hash_ratio = %s
                 where dump_id = %s """,
                (bgp_benign_downloads, bgp_malware_downloads,
                 bgp_suspicious_downloads,
                 bgp_total_downloads, bgp_malware_ratio,
                 bgp_suspicious_ratio,
                 bgp_benign_ratio,
                 bgp_avg_av_labels, bgp_avg_trusted_labels,
                 bgp_unknown_hashes, bgp_total_hashes,
                 bgp_unknown_hash_ratio, dump_id))

        cursor.execute("""
                UPDATE weka_features_sketch set bgp_benign_downloads = %s,
                 bgp_malware_downloads = %s,
                 bgp_suspicious_downloads = %s,
                 bgp_total_downloads = %s,
                 bgp_malware_ratio = %s,
                 bgp_suspicious_ratio = %s,
                 bgp_benign_ratio = %s,
                 bgp_avg_av_labels = %s,
                 bgp_avg_trusted_labels = %s,
                 bgp_unknown_hashes = %s,
                 bgp_total_hashes = %s,
                 bgp_unknown_hash_ratio = %s
                 where dump_id = %s """,
                (bgp_benign_downloads_sketch, bgp_malware_downloads_sketch,
                 bgp_suspicious_downloads_sketch,
                 bgp_total_downloads_sketch, bgp_malware_ratio_sketch,
                 bgp_suspicious_ratio_sketch,
                 bgp_benign_ratio_sketch,
                 bgp_avg_av_labels_sketch, bgp_avg_trusted_labels_sketch,
                 bgp_unknown_hashes_sketch, bgp_total_hashes_sketch,
                 bgp_unknown_hash_ratio_sketch, dump_id))
    except:
        print "Could not insert bgp based features for the dump #", dump_id


def insert_hash_based_features(cursor, dump_id, min_id):
    cursor.execute("""select sha1 from pe_dumps where dump_id = %s""",
                   (dump_id, ))
    sha1 = cursor.fetchone()[0]
    if sha1 is None:
        return
    cursor.execute("""
        SELECT EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))),
            COUNT(DISTINCT pe.dump_id)
        FROM pe_dumps AS pe
        WHERE pe.dump_id > %s AND
            pe.sha1 = %s AND
            pe.corrupt = 'f' """,
        (min_id, sha1))
    hash_life_time, num_dumps_with_same_hash = cursor.fetchone()

    sketch = util.deserialize_sketch('hash_life_time.p')
    hash_life_time_sketch = float(sketch.get(sha1))
    sketch = util.deserialize_sketch('num_dumps_with_same_hash.p')
    num_dumps_with_same_hash_sketch = float(sketch.get(sha1))


    if hash_life_time is None:
        hash_life_time = 0
    if num_dumps_with_same_hash is None:
        num_dumps_with_same_hash = 0

    cursor.execute("""
        UPDATE weka_features
        SET hash_life_time = %s,
            num_dumps_with_same_hash = %s
        WHERE dump_id = %s""",
        (hash_life_time, num_dumps_with_same_hash, dump_id))

    cursor.execute("""
        UPDATE weka_features_sketch
        SET hash_life_time = %s,
            num_dumps_with_same_hash = %s
        WHERE dump_id = %s""",
        (hash_life_time_sketch, num_dumps_with_same_hash_sketch, dump_id))

    cursor.execute("""
        SELECT count(*) FROM
            (SELECT DISTINCT client,
                DATE_TRUNC('DAY', timestamp)
            FROM pe_dumps AS pe
            WHERE pe.dump_id > %s AND
                pe.corrupt='f' AND
                pe.sha1 = %s) AS a""",
        (min_id, sha1))
    estimated_clients_with_same_hash = cursor.fetchone()[0]

    if estimated_clients_with_same_hash is None:
       estimated_clients_with_same_hash_sketch = None
    else:
        sketch = util.deserialize_sketch('estimated_clients_same_hash.p')
        estimated_clients_with_same_hash_sketch = float(sketch.get(sha1))

    cursor.execute("""
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
        (min_id, sha1))
    hash_daily_dump_rate_per_client = cursor.fetchone()[0]

    if hash_daily_dump_rate_per_client is None:
        hash_daily_dump_rate_per_client_sketch = None
    else:
        sketch = util.deserialize_sketch('hash_daily_dump_rate.p')
        hash_daily_dump_rate_per_client_sketch = float(sketch.get(sha1))



    cursor.execute("""
        UPDATE weka_features
        SET estimated_clients_with_same_hash = %s,
            hash_daily_dump_rate_per_client = %s
        WHERE dump_id = %s""",
        (estimated_clients_with_same_hash, hash_daily_dump_rate_per_client,
        dump_id))

    cursor.execute("""
        UPDATE weka_features_sketch
        SET estimated_clients_with_same_hash = %s,
            hash_daily_dump_rate_per_client = %s
        WHERE dump_id = %s""",
        (estimated_clients_with_same_hash_sketch, hash_daily_dump_rate_per_client_sketch,
        dump_id))


def insert_download_request_features(cursor, dump_id):
    cursor.execute("""
        SELECT *
        FROM pe_dumps
        WHERE dump_id = %s AND
            referer IS null""",
        (dump_id,))
    if cursor.rowcount == 1:
        referer_exists = 0
    else:
        referer_exists = 1

    # update weka_features as wf set host_name_exists=0 from pe_dumps as pe
    # where pe.dump_id = wf.dump_id and host SIMILAR TO
    # '[0-9]+.[0-9]+.[0-9]+.[0-9]+'
    cursor.execute("""
        SELECT *
        FROM pe_dumps
        WHERE dump_id = %s AND
            host = SUBSTRING(CAST(server AS TEXT) FROM '(.*)/32')""",
        (dump_id,))
    if cursor.rowcount == 0:
        host_name_exists = 1
    else:
        host_name_exists = 0

    cursor.execute("""
        UPDATE weka_features
        SET referer_exists = %s,
            host_name_exists = %s
        WHERE dump_id = %s""",
        (referer_exists, host_name_exists, dump_id))
    cursor.execute("""
        UPDATE weka_features_sketch
        SET referer_exists = %s,
            host_name_exists = %s
        WHERE dump_id = %s""",
        (referer_exists, host_name_exists, dump_id))

    # Once we generalize to file types beyond PE files, the extension_class feature should probably be removed
    common_ext = ['exe', 'dll', 'msi', 'jar', 'dmg', 'apk'] # executable files extensions...
    common_fake = ['html', 'gif', 'jpg', 'jpeg', 'txt', 'pdf', 'htm']
    other_ext = ['php', 'aspx', 'asp']

    cursor.execute("""
        SELECT url
        FROM pe_dumps
        WHERE dump_id = %s""",
        (dump_id,))
    url = cursor.fetchone()[0]
    if url is not None:
        ext = util.extract_extension(url)
        if ext is not None:
            ext = ext[:10]

        if ext is None:
            ext_class = "no_ext"
        elif ext in common_ext:
            ext_class = "common_ext"
        elif ext in common_fake:
            ext_class = "common_fake"
        elif ext in other_ext:
            ext_class = "other_ext"
        else:
            ext_class = "unknown_ext"
        #print "url:", url
        #print "extension:", ext
    else:
        ext_class = "no_url"
        ext = None
    cursor.execute("""
        UPDATE weka_features
        SET extension_class = %s
        WHERE dump_id = %s""",
        (ext_class, dump_id))

    cursor.execute("""
        UPDATE weka_features_sketch
        SET extension_class = %s
        WHERE dump_id = %s""",
        (ext_class, dump_id))


    cursor.execute("""
        SELECT CHAR_LENGTH(url), url
        FROM pe_dumps
        WHERE dump_id = %s""",
        (dump_id,))
    row = cursor.fetchone()
    url_length = None
    if row is not None:
        url_length = row[0]
        url = row[1]
        if url is not None:
            url_path = url.split('?')[0]
            directory_depth = url_path.count('/')
        else:
            url_length = 0
            directory_depth = 0

    cursor.execute("""
            UPDATE weka_features SET
            url_length = %s,
            directory_depth = %s
            WHERE dump_id = %s""",
            (url_length, directory_depth, dump_id))

    cursor.execute("""
            UPDATE weka_features_sketch SET
            url_length = %s,
            directory_depth = %s
            WHERE dump_id = %s""",
            (url_length, directory_depth, dump_id))


def insert_url_features(cursor, dump_id, min_id):

    cursor.execute("SELECT url from pe_dumps where dump_id = %s", (dump_id,))
    url = cursor.fetchone()[0]
    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.trusted_av_labels > 1 AND
            pe.url = %s AND
            pe.dump_id > %s AND
            pvm.vt_id = vts.vt_id """,
        (url, min_id))
    url_malware_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('url_malware.p')
    url_malware_downloads_sketch = int(sketch.get(url))

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe
        WHERE pe.url = %s AND
            pe.dump_id > %s """,
        (url, min_id))
    url_total_downloads = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('url_total.p')
    url_total_downloads_sketch = int(sketch.get(url))

    cursor.execute("""
        SELECT COUNT(DISTINCT pe.sha1)
        FROM pe_dumps AS pe
        WHERE pe.url = %s AND
            pe.dump_id > %s AND
            pe.corrupt='f' """,
        (url, min_id))
    url_distinct_sha1s = cursor.fetchone()[0]

    sketch = util.deserialize_sketch('url_distinct_sha1s.p')
    url_distinct_sha1_sketch = int(sketch.get(url))

    cursor.execute("""
        UPDATE weka_features
        SET url_malware_downloads = %s,
            url_total_downloads = %s,
            url_distinct_sha1s = %s
        WHERE dump_id = %s """,
    (url_malware_downloads, url_total_downloads,
    url_distinct_sha1s, dump_id))

    cursor.execute("""
        UPDATE weka_features_sketch
        SET url_malware_downloads = %s,
            url_total_downloads = %s,
            url_distinct_sha1s = %s
        WHERE dump_id = %s """,
    (url_malware_downloads_sketch, url_total_downloads_sketch,
    url_distinct_sha1_sketch, dump_id))


def get_url_struct_matches(cursor, url_struct, dump_id, min_id):
    # escaping special regex characters
    replace = [
               ('.', '\.'), ('+', '\+'), ('?', '\?'),
               ('{', '\{'), ('}', '\}'), ('[', '\]'),
               ('[', '\]'), ('^', '\^'), ('$', '\$')
              ]
    for pair in replace:
        url_struct = url_struct.replace(pair[0], pair[1])
    # the structure should be a matched to the whole query path
    url_struct = '^.*\?' + url_struct + '$'
    #print "The formatted url_struct: %s" % (url_struct,)
    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.trusted_av_labels > 1 AND
            pvm.vt_id = vts.vt_id AND
            pe.url ~ %s AND
            pe.dump_id > %s """,
        (url_struct, min_id))
    url_struct_malware_downloads = cursor.fetchone()[0]


    cursor.execute("""
        SELECT DISTINCT pe.url, pe.host
        FROM pe_dumps AS pe JOIN
            ped_vts_mapping AS pvm USING (dump_id),
            virus_total_scans AS vts
        WHERE vts.trusted_av_labels > 1 AND
            pe.url ~ %s AND
            pe.dump_id > %s """,
        (url_struct, min_id))
    urls = cursor.fetchall()
    #print "the urls:"
    #for url in urls:
        #print url[0], url[1]

    cursor.execute("""
        SELECT COUNT(DISTINCT dump_id)
        FROM pe_dumps AS pe
        WHERE pe.url ~ %s AND
            pe.dump_id > %s """,
        (url_struct, min_id))
    url_struct_total_downloads = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(DISTINCT pe.sha1)
        FROM pe_dumps AS pe
        WHERE pe.url ~ %s AND
            pe.dump_id > %s AND
            pe .corrupt='f' """,
        (url_struct, min_id))
    url_struct_distinct_sha1s = cursor.fetchone()[0]
    return (url_struct_malware_downloads, url_struct_total_downloads,
            url_struct_distinct_sha1s)


def insert_url_struct_matches(cursor, pmd, ptd, pds, dump_id):
    sql_query = "UPDATE weka_features " \
                "SET url_struct_malware_downloads = %s, " \
                "url_struct_total_downloads = %s, " \
                "url_struct_distinct_sha1s = %s " \
                "WHERE dump_id = %s" % \
                (pmd, ptd, pds, dump_id)
    cursor.execute(sql_query)

def insert_url_struct_matches_sketch(cursor, pmd, ptd, pds, dump_id):
    sql_query = "UPDATE weka_features_sketch " \
                "SET url_struct_malware_downloads = %s, " \
                "url_struct_total_downloads = %s, " \
                "url_struct_distinct_sha1s = %s " \
                "WHERE dump_id = %s" % \
                (pmd, ptd, pds, dump_id)
    cursor.execute(sql_query)


def insert_url_struct_features(cursor, dump_id,min_id):
    cursor.execute("""
                SELECT url from pe_dumps where dump_id = %s""", (dump_id,))
    url = cursor.fetchone()
    if url is None:
        return

    url = url[0]
    if url is None:
        return


    #print "The url is: ", url
    #print "Dump_id is ", dump_id
    #print "The parsed result is:", urlparse.urlparse(url)
    parsed_url = urlparse.urlparse(url)
    path = parsed_url.path
    #print "Path: ", path
    query = parsed_url.query
    query_list = urlparse.parse_qsl(query, keep_blank_values=True)
    #print "The parsed query is:",query_list

    #print "Query is: %s" % query
    m = re.search('([^\w]*)([\w]+)([^\w]+)(.*)', query)
    if m is None:
        print "No url_struct found!"
        return
    first_exp = m.group(1)
    word = m.group(2)
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
            word = m.group(1)
            divide = m.group(2)
            #if '.' in divide:
            #print "divide:", divide
            rest = m.group(3)
            if divide:
                url_struct += "\w*" + divide
            else:
                url_struct += "\w*"
        else: break

    #print "url_struct :", url_struct
    if len(url_struct) < 10:
        print "url_struct pattern length too short:%s, " % len(url_struct), url_struct
        return

    pmd, ptd, pds = get_url_struct_matches(cursor, url_struct, dump_id, min_id)
    print "Number of url_struct matching dumps: %s/%s" % (pmd,ptd)
    insert_url_struct_matches(cursor, pmd, ptd, pds, dump_id)
    sketch = util.deserialize_sketch('url_struct_malware_downloads.p')
    url_struct_malware_downloads_sketch = int(sketch.get(url))
    sketch = util.deserialize_sketch('url_struct_total_downloads.p')
    url_struct_total_downloads_sketch = int(sketch.get(url))
    sketch = util.deserialize_sketch('url_struct_distinct_sha1s.p')
    url_struct_distinct_sha1s_sketch = int(sketch.get(url))
    insert_url_struct_matches_sketch(cursor, url_struct_malware_downloads_sketch, url_struct_total_downloads_sketch
                                     , url_struct_distinct_sha1s_sketch, dump_id)



def insert_features(cursor, dump_id, min_id):
    print "the dump_id is:", dump_id
    cursor.execute("""
        DELETE FROM weka_features
        WHERE dump_id = %s
        """, (dump_id,))
    cursor.execute("""
    INSERT INTO weka_features (dump_id, corrupt, sha1, host)
        (SELECT pe.dump_id, pe.corrupt, pe.sha1, pe.host
            FROM pe_dumps AS pe
            WHERE pe.dump_id = %s )""",
        (dump_id,))

    cursor.execute("""
        DELETE FROM weka_features_sketch
        WHERE dump_id = %s
        """, (dump_id,))
    cursor.execute("""
    INSERT INTO weka_features_sketch (dump_id, corrupt, sha1, host)
        (SELECT pe.dump_id, pe.corrupt, pe.sha1, pe.host
            FROM pe_dumps AS pe
            WHERE pe.dump_id = %s )""",
        (dump_id,))
    #print "Inserted dump_id", cursor.fetchone()[0]

    insert_host_based_features(cursor, dump_id, min_id)
    insert_server_ip_based_features(cursor, dump_id, min_id)
    insert_bgp_based_features(cursor, dump_id, min_id)
    insert_twold_based_features(cursor, dump_id, min_id)
    insert_hash_based_features(cursor, dump_id, min_id)
    insert_download_request_features(cursor, dump_id)
    insert_url_features(cursor, dump_id, min_id)
    try:
        insert_url_struct_features(cursor, dump_id, min_id)
    except psycopg2.DataError as e:
        print "Exception in inserting url_struct features for %s dump_id" % (dump_id,)
        print e


def get_feature_vector(dump_id,file_extension, min_id):
    #print "entered get_feature_vector"
    conn = util.connect_to_db()
    cursor = conn.cursor()
    insert_features(cursor, dump_id, min_id)
    print "Done inserting features for dump_id: ", dump_id

if __name__ == "__main__":
    if len(sys.argv) == 3:
        get_feature_vector(sys.argv[1],sys.argv[2])
    else:
        print "Incorrect number of arguments!!"
