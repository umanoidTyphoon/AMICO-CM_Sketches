__author__ = 'umanoidTyphoon'

from collections import defaultdict

import util

CLASSIFICATION_GRAPH_ID = 4
DOWNLOAD_GRAPH_ID       = 1
MAP_GRAPH_ID            = 2
TRAFFIC_GRAPH_ID        = 0
TRAINING_GRAPH_ID       = 3

AMICO_THRESHOLD = 0.4


def generate_graph(graph_id):
    if graph_id == TRAFFIC_GRAPH_ID:
        generate_CSV_traffic_file()
        return
    if graph_id == DOWNLOAD_GRAPH_ID:
        generate_CSV_download_file()
        return
    if graph_id == MAP_GRAPH_ID:
        generate_CSV_map_file()
        return
    if graph_id == TRAINING_GRAPH_ID:
        generate_CSV_training_file()
        return
    if graph_id == CLASSIFICATION_GRAPH_ID:
        generate_CSV_classification_file()
        return

def generate_CSV_download_file():
    connection = util.connect_to_db()
    connection_cursor = connection.cursor()

    csv_map = defaultdict(list)
    malware_timestamp_set = set()
##################################################### EXECUTABLES #####################################################

    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'APK' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            malware_apk_count_per_second = row[1]

            csv_map[timestamp].append(malware_apk_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'APK' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            total_apk_count_per_second = row[1]

            if malware_timestamp_set.__contains__(timestamp):
                csv_map[timestamp].append(total_apk_count_per_second)
            else:
                csv_map[timestamp].extend([0, total_apk_count_per_second])


    malware_timestamp_set = set()
    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'DMG' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            malware_dmg_count_per_second = row[1]

            csv_map[timestamp].append(malware_dmg_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'DMG' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            total_dmg_count_per_second = row[1]

            if malware_timestamp_set.__contains__(timestamp):
                csv_map[timestamp].append(total_apk_count_per_second)
            else:
                csv_map[timestamp].extend([0, total_apk_count_per_second])


    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'ELF' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    total_elf = connection_cursor.fetchone()[0]

    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'ELF' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    malware_elf = connection_cursor.fetchone()[0]


    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'EXE' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    total_exe = connection_cursor.fetchone()[0]

    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'EXE' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    malware_exe = connection_cursor.fetchone()[0]

########################################################################################################################

######################################################### PDF #########################################################

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'PDF' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    total_pdf = connection_cursor.fetchone()[0]

    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'PDF' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    malware_pdf = connection_cursor.fetchone()[0]

########################################################################################################################

######################################################## FLASH ########################################################

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'SWF' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    total_swf = connection_cursor.fetchone()[0]

    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'SWF' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    malware_swf = connection_cursor.fetchone()[0]

########################################################################################################################

###################################################### COMPRESSED ######################################################

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'JAR' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    total_jar = connection_cursor.fetchone()[0]

    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'JAR' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    malware_jar = connection_cursor.fetchone()[0]


    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'RAR' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    total_rar = connection_cursor.fetchone()[0]

    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'RAR' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    malware_rar = connection_cursor.fetchone()[0]


    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'ZIP' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    total_zip = connection_cursor.fetchone()[0]

    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'ZIP' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    malware_zip = connection_cursor.fetchone()[0]

########################################################################################################################

    #TODO Da cambiare ordine malware legitimate
    header = "Second_ID, Tot_APK,Mal_APK,Tot_DMG,Mal_DMG,Tot_ELF,Mal_ELF,Tot_EXE,Mal_EXE,Tot_PDF,Mal_PDF,Tot_SWF," + \
             "Mal_SWF,Tot_JAR,Mal_JAR,Tot_RAR,Mal_RAR,Tot_ZIP,Mal_ZIP, Timestamp"

# def test_graph_generation():
graph_id = DOWNLOAD_GRAPH_ID
generate_graph(graph_id)