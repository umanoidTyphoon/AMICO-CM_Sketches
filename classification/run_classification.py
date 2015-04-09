__author__ = 'vincenzo'
from build_weka_database import build
from classify import classify_dump

import util


build(10000)

conn = util.connect_to_db()

cursor = conn.cursor()

cursor.execute("""SELECT max(dump_id) from pe_dumps""")
lastID = cursor.fetchone()[0]

currID = lastID - 10000

while currID < lastID:
    classify_dump(currID)
    currID += 1

