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
                csv_map[timestamp].append(total_dmg_count_per_second)
            else:
                csv_map[timestamp].extend([0, total_dmg_count_per_second])


    malware_timestamp_set = set()
    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'ELF' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            malware_elf_count_per_second = row[1]

            csv_map[timestamp].append(malware_elf_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'ELF' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            total_elf_count_per_second = row[1]

            if malware_timestamp_set.__contains__(timestamp):
                csv_map[timestamp].append(total_elf_count_per_second)
            else:
                csv_map[timestamp].extend([0, total_elf_count_per_second])


    malware_timestamp_set = set()
    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'EXE' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            malware_exe_count_per_second = row[1]

            csv_map[timestamp].append(malware_exe_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'EXE' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            total_exe_count_per_second = row[1]

            if malware_timestamp_set.__contains__(timestamp):
                csv_map[timestamp].append(total_exe_count_per_second)
            else:
                csv_map[timestamp].extend([0, total_exe_count_per_second])

########################################################################################################################

######################################################### PDF #########################################################

    malware_timestamp_set = set()
    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'PDF' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            malware_pdf_count_per_second = row[1]

            csv_map[timestamp].append(malware_pdf_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'PDF' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            total_pdf_count_per_second = row[1]

            if malware_timestamp_set.__contains__(timestamp):
                csv_map[timestamp].append(total_pdf_count_per_second)
            else:
                csv_map[timestamp].extend([0, total_pdf_count_per_second])

########################################################################################################################

######################################################## FLASH ########################################################

    malware_timestamp_set = set()
    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'SWF' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            malware_swf_count_per_second = row[1]

            csv_map[timestamp].append(malware_swf_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'SWF' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            total_swf_count_per_second = row[1]

            if malware_timestamp_set.__contains__(timestamp):
                csv_map[timestamp].append(total_swf_count_per_second)
            else:
                csv_map[timestamp].extend([0, total_swf_count_per_second])

########################################################################################################################

###################################################### COMPRESSED ######################################################

    malware_timestamp_set = set()
    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'JAR' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            malware_jar_count_per_second = row[1]

            csv_map[timestamp].append(malware_jar_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'JAR' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            total_jar_count_per_second = row[1]

            if malware_timestamp_set.__contains__(timestamp):
                csv_map[timestamp].append(total_jar_count_per_second)
            else:
                csv_map[timestamp].extend([0, total_jar_count_per_second])


    malware_timestamp_set = set()
    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'RAR' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            malware_rar_count_per_second = row[1]

            csv_map[timestamp].append(malware_rar_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'RAR' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            total_rar_count_per_second = row[1]

            if malware_timestamp_set.__contains__(timestamp):
                csv_map[timestamp].append(total_rar_count_per_second)
            else:
                csv_map[timestamp].extend([0, total_rar_count_per_second])


    malware_timestamp_set = set()
    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'ZIP' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            malware_zip_count_per_second = row[1]

            csv_map[timestamp].append(malware_zip_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'ZIP' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = row[0]
            total_zip_count_per_second = row[1]

            if malware_timestamp_set.__contains__(timestamp):
                csv_map[timestamp].append(total_zip_count_per_second)
            else:
                csv_map[timestamp].extend([0, total_zip_count_per_second])

########################################################################################################################

    header = "Second_ID,Mal_APK,Tot_APK,Mal_DMG,Tot_DMG,Mal_ELF,Tot_ELF,Mal_EXE,Tot_EXE,Mal_PDF,Tot_PDF,Mal_SWF," + \
             "Tot_SWF,Mal_JAR,Tot_JAR,Mal_RAR,Tot_RAR,Mal_ZIP,Tot_ZIP, Timestamp"

# def test_graph_generation():
graph_id = DOWNLOAD_GRAPH_ID
generate_graph(graph_id)