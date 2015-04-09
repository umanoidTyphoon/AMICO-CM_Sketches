"""
Utility functions
"""
import psycopg2
import re
import etld
import pickle
import dill
import numpy as np

from config import *


def connect_to_db():
    try:
        conn = psycopg2.connect("dbname={0:s} host={1:s} user={2:s} password={3:s}"
                                .format(db_name, db_host, db_user, db_password))
    except Exception as e:
        print "Unable to connect to database: " + db_name
        print e
        return
    conn.set_isolation_level(0)
    return conn


def log(feature_name,dir, total_elements, total_error, maximum_error, avg_error, variance, std_deviation, mean_value,
        error_rate, variance_rate):

    """

    :rtype : none
    """
    out_file = open("./output/%s/%s.out" % (dir, feature_name ), "w")
    out_file.write("%s\n\n" % feature_name)
    out_file.write("Total number of elements: %d \n" % total_elements)
    out_file.write("Total error: %f \n" % total_error)
    out_file.write("Maximum error: %f \n" % maximum_error)
    out_file.write("Average error: %f \n" % avg_error)
    out_file.write("Variance: %f \n" % variance)
    out_file.write("Standard deviation: %f \n" % std_deviation)
    out_file.write("Mean value: %f \n" % mean_value)
    out_file.write("Error rate: %f \n" % error_rate)
    out_file.write("Variance rate: %f \n" % variance_rate)
    out_file.close()
    return


def reorder_domain(host):
    if host is None:
        return
    try:
        host = host.split(':')[0]  # in case host string contains port
        ipreg = re.compile("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
        if ipreg.match(host) is None:
            ordered_host = ""
            host += '.'
            domains = re.findall('.*?\.', host)
            for i in range(len(domains)):
                ordered_host += domains[len(domains) - i - 1]
            ordered_host = ordered_host[:-1]
            return ordered_host
        else:
            return host
    except Exception as e:
        print "exception in reorder_domain for host: %s" % (host,)
        print e
        return host


def extract_twold(url):
    etld_obj = etld.etld()
    registered, suffix = etld_obj.parse(url)
    twold = '.'.join([registered.split('.')[-1], suffix])
    return twold


def is_ip(string):
    ipreg = re.compile("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
    if ipreg.match(string) is not None:
        return True
    else:
        return False


def get_url_struct_matches(cursor, url_struct, start_id):
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
    # print "The formatted url_struct: %s" % (url_struct,)
    try:
        cursor.execute("""
            SELECT COUNT(DISTINCT dump_id)
            FROM pe_dumps AS pe JOIN
                ped_vts_mapping AS pvm USING (dump_id),
                virus_total_scans AS vts
            WHERE vts.trusted_av_labels > 1 AND
                pvm.vt_id = vts.vt_id AND
                pe.url ~ %s AND
                pe.dump_id > %s """,
                       (url_struct, start_id))
        url_struct_malware_downloads = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(DISTINCT dump_id)
            FROM pe_dumps AS pe
            WHERE pe.url ~ %s AND
                pe.dump_id > %s """,
                       (url_struct, start_id))
        url_struct_total_downloads = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(DISTINCT pe.sha1)
            FROM pe_dumps AS pe
            WHERE pe.url ~ %s AND
                pe.dump_id > %s AND
                pe .corrupt='f' """,
                       (url_struct, start_id))

        url_struct_distinct_sha1s = cursor.fetchone()[0]
    except Exception as e:
        print "Unable to parse %s" % url_struct
        url_struct_malware_downloads = url_struct_distinct_sha1s = url_struct_total_downloads = 0
    return (url_struct_malware_downloads, url_struct_total_downloads,
            url_struct_distinct_sha1s)

def serialize_sketch(name, sketch):
    output = open("./serialized/%s" % name, 'wb')
    pickle.dump(sketch, output)
    output.close()

    return pickle.load(open("./serialized/%s" % name, 'rb'))

def deserialize_sketch(name):
    """

    :rtype : Sketch
    """
    return pickle.load(open("./serialized/%s" % name,'rb'))

def serialize_twold(twold_mapping, twold_list):
    output = open("./twold_mapping.p", 'wb')
    pickle.dump(twold_mapping, output)
    output.close()

    output = open("./twold_list.p", 'wb')
    pickle.dump(twold_list, output)
    output.close()

    return pickle.load(open("./twold_mapping.p", 'rb')), pickle.load(open("./twold_list.p", 'rb'))


def extract_extension(url):
    file_name = url.split('?')[0].split('/')[-1]
    if '.' in file_name:
        ext = file_name.split('.')[-1]
        return ext
    else:
        return None

def update_results(res, res_sketch):
    out_file = open("./classification.out", "a")
    out_file.write("%s : %s\n" % (res, res_sketch))
    out_file.close()

def fetch_classification():
    f = open("./classification.out", "r")
    lines = f.readlines()
    max_diff = 0.0
    total_diff = 0.0
    misclassified = 0
    identical = 0
    list = []
    differences = []

    plot = []

    for line in lines:
        db_class = float(line[:line.rindex(":")])
        sketch_class = float(line[line.rindex(":")+2:])

        diff = abs(db_class - sketch_class)

        differences.append(diff)

        if diff > max_diff:
            max_diff = diff
        total_diff += diff

        if diff > 0.10:
            list.append([db_class, sketch_class])
            misclassified += 1

        if db_class == sketch_class:
            identical += 1

        plot.append(diff)

    print "Average difference: %f" % np.average(differences)
    print "Variance: %f" % np.var(differences)
    print "Standard deviation: %f" % np.std(differences)
    print "Number of miscalssified elements: %d" % misclassified
    print "Values of misclassified elements: ", list
    print "Max difference: %f" %max_diff
    print "Number of identically classified elements: %d" % identical

    return plot, np.average(differences), np.var(differences), np.std(differences)