__author__ = 'vincenzo'

import util
import db_extraction
import pickle
import dill
import re
import urlparse
import numpy as np


for i in range(11):
    sketch = pickle.load(open("./%d/url_struct_total_downloads-%d.p" % (i,i),'rb'))
    db = db_extraction.DBextraction()

    conn = util.connect_to_db()
    cursor = conn.cursor()
    inner_cursor = conn.cursor()

    start_id = db.maxID - 10000

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

            db.url_struct_total_downloads[url] = ptd

    temp_tot, error_list, total_error, max_error = db_extraction.compute_stats(db.url_struct_total_downloads.iteritems(), sketch)

    mean_value = temp_tot / error_list.size
    avg_error = np.mean(error_list)
    error_rate = avg_error / mean_value * 100

    print "Error expected: %d - Obtained: %f" %(i, error_rate)

