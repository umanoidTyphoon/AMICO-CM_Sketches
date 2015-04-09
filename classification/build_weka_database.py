__author__ = 'vincenzo'
from get_feature_vector_from_sketch import get_feature_vector
import util


def build(window):
    conn = util.connect_to_db()

    cursor = conn.cursor()

    cursor.execute("""SELECT max(dump_id) from pe_dumps""")
    lastID = cursor.fetchone()[0]

    minID = lastID - window
    currID = lastID - window


    while currID < lastID:
        cursor.execute("""SELECT file_type FROM
                                        pe_dumps WHERE
                                        dump_id=%d""" % (currID,))
        file_extension = cursor.fetchone()[0]
        get_feature_vector(currID,file_extension, minID)
        currID += 1