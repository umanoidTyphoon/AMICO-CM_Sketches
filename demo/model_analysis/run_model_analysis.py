__author__ = 'umanoidTyphoon'
from build_weka_database import build
from classifier_model_analyzer import classify_dump
from weka.classifiers import Classifier

import util
import weka.core.jvm as jvm
import weka.core.serialization as serialization

# WINDOW_WIDTH = 10000
WINDOW_WIDTH = 25

jvm.start()

deserialized_objects = serialization.read_all("default.model")
classifier = Classifier(jobject=deserialized_objects[0])

print classifier

jvm.stop()

# build(WINDOW_WIDTH)
#
# conn = util.connect_to_db()
#
# cursor = conn.cursor()
#
# cursor.execute("""SELECT max(dump_id) from pe_dumps""")
# lastID = cursor.fetchone()[0]
#
# currID = lastID - WINDOW_WIDTH
#
# while currID < lastID:
#     classify_dump(currID)
#     currID += 1

