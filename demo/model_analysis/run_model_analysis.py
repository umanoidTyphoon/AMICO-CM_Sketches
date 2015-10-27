__author__ = 'umanoidTyphoon'
from build_weka_database import build
from classifier_model_analyzer import classify_dump

import util

# WINDOW_WIDTH = 10000
WINDOW_WIDTH = 25

build(WINDOW_WIDTH)

conn = util.connect_to_db()

cursor = conn.cursor()

cursor.execute("""SELECT max(dump_id) from pe_dumps""")
lastID = cursor.fetchone()[0]

currID = lastID - WINDOW_WIDTH

while currID < lastID:
    classify_dump(currID)
    currID += 1

