__author__ = 'umanoidTyphoon'

from collections import defaultdict
from datetime    import datetime
from time        import time

import csv
import operator
import util

CLASSIFICATION_GRAPH_ID = 4
DOWNLOAD_GRAPH_ID       = 1
MAP_GRAPH_ID            = 2
TRAFFIC_GRAPH_ID        = 0
TRAINING_GRAPH_ID       = 3

AMICO_THRESHOLD = 0.4
OUT_DIR = "./out"


def generate_graph(graph_id):
    if graph_id == TRAFFIC_GRAPH_ID:
        generate_CSV_traffic_file()
        return
    if graph_id == DOWNLOAD_GRAPH_ID:
        generate_CSV_download_file()
        return
    if graph_id == MAP_GRAPH_ID:
        generate_JSON_map_file()
        return
    if graph_id == TRAINING_GRAPH_ID:
        generate_CSV_training_file()
        return
    if graph_id == CLASSIFICATION_GRAPH_ID:
        generate_CSV_classification_file()
        return


def format_row(value_list, max_values):
    list_size      = len(value_list)
    max_iterations = max_values - list_size

    for iteration in range(max_iterations):
        value_list.append(0)

    return value_list

def generate_CSV_download_file():
    connection = util.connect_to_db()
    connection_cursor = connection.cursor()
    csv_writer = None

    header = "Second_ID,Mal_APK,Tot_APK,Mal_DMG,Tot_DMG,Mal_ELF,Tot_ELF,Mal_EXE,Tot_EXE,Mal_PDF,Tot_PDF,Mal_SWF," + \
             "Tot_SWF,Mal_JAR,Tot_JAR,Mal_RAR,Tot_RAR,Mal_ZIP,Tot_ZIP,Timestamp,Next_Download_Event_[s]"
    header_list = ["Second_ID", "Mal_APK", "Tot_APK", "Mal_DMG", "Tot_DMG", "Mal_ELF", "Tot_ELF", "Mal_EXE", "Tot_EXE",
                   "Mal_PDF", "Tot_PDF", "Mal_SWF", "Tot_SWF", "Mal_JAR", "Tot_JAR", "Mal_RAR", "Tot_RAR", "Mal_ZIP",
                   "Tot_ZIP", "Timestamp", "Next_Download_Event_[s]"]
    created_csv_file = OUT_DIR + "/" + str(DOWNLOAD_GRAPH_ID) + "-downloads_" + \
                       datetime.fromtimestamp(time()).strftime('%Y-%m-%d_%H-%M-%S') + ".csv"

    with open(created_csv_file, "wb") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(header_list)

    csv_map = defaultdict(list)
    malware_timestamp_set = set()
    ##################################################### EXECUTABLES #####################################################

    query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
            """pe.dump_id = ams.dump_id AND pe.file_type = 'APK' AND ams.score > """ + str(AMICO_THRESHOLD) + \
            """GROUP BY  timestamp ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = str(row[0])
            malware_apk_count_per_second = row[1]

            csv_map[timestamp].append(malware_apk_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'APK' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = str(row[0])
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
            timestamp = str(row[0])
            malware_dmg_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0])

            csv_map[timestamp].append(malware_dmg_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'DMG' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = str(row[0])
            total_dmg_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0])

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
            timestamp = str(row[0])
            malware_elf_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0])

            csv_map[timestamp].append(malware_elf_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'ELF' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = str(row[0])
            total_elf_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0])

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
            timestamp = str(row[0])
            malware_exe_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0])

            csv_map[timestamp].append(malware_exe_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'EXE' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = str(row[0])
            total_exe_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0])

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
            timestamp = str(row[0])
            malware_pdf_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0, 0, 0])

            csv_map[timestamp].append(malware_pdf_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'PDF' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = str(row[0])
            total_pdf_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0, 0, 0])

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
            timestamp = str(row[0])
            malware_swf_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

            csv_map[timestamp].append(malware_swf_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'SWF' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = str(row[0])
            total_swf_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

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
            timestamp = str(row[0])
            malware_jar_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

            csv_map[timestamp].append(malware_jar_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'JAR' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = str(row[0])
            total_jar_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

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
            timestamp = str(row[0])
            malware_rar_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

            csv_map[timestamp].append(malware_rar_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'RAR' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = str(row[0])
            total_rar_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

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
            timestamp = str(row[0])
            malware_zip_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

            csv_map[timestamp].append(malware_zip_count_per_second)
            malware_timestamp_set.add(timestamp)

    query = """SELECT timestamp, COUNT(file_type) FROM pe_dumps WHERE file_type = 'ZIP' GROUP BY  timestamp """ + \
            """ORDER BY timestamp ASC"""
    connection_cursor.execute(query)

    for row in connection_cursor:
        if row is not None:
            timestamp = str(row[0])
            total_zip_count_per_second = row[1]

            if timestamp not in csv_map:
                csv_map[timestamp].extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

            if malware_timestamp_set.__contains__(timestamp):
                csv_map[timestamp].append(total_zip_count_per_second)
            else:
                csv_map[timestamp].extend([0, total_zip_count_per_second])

            ########################################################################################################################
    sorted_csv_map = sorted(csv_map.items(), key=operator.itemgetter(0))

    csv_map_aux = defaultdict(list)
    first_useful_date = "2014-11-26 22:55:40"
    last_useful_date  = "2015-10-01 00:00:00"
    # Loop for handling corrupted timestamp
    for timestamp, file_list in sorted_csv_map:
        if cmp(timestamp, first_useful_date) < 0:
            timestamp_split         = timestamp.split()
            first_useful_date_split = first_useful_date.split()
            timestamp_hms           = timestamp_split[1]
            first_useful_date_ymd   = first_useful_date_split[0]

            corrected_timestamp = first_useful_date_ymd + " " + timestamp_hms
            csv_map_aux[corrected_timestamp] = csv_map.get(timestamp)
        else:
            break

    max_values = len(header.split(',')) - 2
    next_download_events = 0
    csv_rows = list()
    csv_rows_list_size  = len(csv_rows)
    sorted_csv_map_aux = sorted(csv_map_aux.items(), key=operator.itemgetter(0))
    UID = 0
    #with open(created_csv_file, "a") as csv_file:
    #    csv_writer = csv.writer(csv_file, csv.QUOTE_NONNUMERIC)

    for timestamp, file_list in sorted_csv_map_aux:
        formatted_row = format_row(file_list, max_values)
        formatted_row.insert(0, UID)
        formatted_row.append(timestamp)
        csv_rows.append(formatted_row)
        UID += 1

    writable_csv_rows = list()
    while csv_rows:
        current_row     = csv_rows.pop(0)
        if not csv_rows:
            writable_csv_rows.append(current_row)
            continue
        next_row        = csv_rows[0]
        timestamp_index = len(current_row) - 1

        current_timestamp_string = current_row[timestamp_index]
        next_timestamp_string    = next_row[timestamp_index]

        current_timestamp  = datetime.strptime(current_timestamp_string, '%Y-%m-%d %H:%M:%S')
        next_timestamp     = datetime.strptime(next_timestamp_string, '%Y-%m-%d %H:%M:%S')
        time_delta_in_secs = int((next_timestamp - current_timestamp).total_seconds()) - 1
        current_row.append(time_delta_in_secs)

        writable_csv_rows.append(current_row)

    writable_sorted_csv_map = list()
    for timestamp, file_list in sorted_csv_map:
        if cmp(timestamp, first_useful_date) < 0 or cmp(timestamp, last_useful_date) > 0:
            continue
        else:
            writable_sorted_csv_map.append([timestamp, file_list])

    writable_csv_rows_aux = list()
    while writable_sorted_csv_map:
        timestamp_file_list_first_pair = writable_sorted_csv_map.pop(0)
        timestamp_str_first_pair       = timestamp_file_list_first_pair[0]
        file_list_first_pair           = timestamp_file_list_first_pair[1]

        if not writable_sorted_csv_map:
            formatted_row = format_row(file_list_first_pair, max_values)
            formatted_row.insert(0, UID)
            formatted_row.append(timestamp_str_first_pair)
            writable_csv_rows_aux.append(formatted_row)
            UID += 1
            continue
        timestamp_file_list_second_pair = writable_sorted_csv_map[0]
        timestamp_str_second_pair       = timestamp_file_list_second_pair[0]

        formatted_row = format_row(file_list_first_pair, max_values)
        formatted_row.insert(0, UID)
        formatted_row.append(timestamp_str_first_pair)

        timestamp_first_pair  = datetime.strptime(timestamp_str_first_pair, '%Y-%m-%d %H:%M:%S')
        timestamp_second_pair = datetime.strptime(timestamp_str_second_pair, '%Y-%m-%d %H:%M:%S')
        time_delta_in_secs = int((timestamp_second_pair - timestamp_first_pair).total_seconds()) - 1
        formatted_row.append(time_delta_in_secs)

        writable_csv_rows_aux.append(formatted_row)
        UID += 1

    last_formatted_row_in_writable_csv_rows      = writable_csv_rows.pop(len(writable_csv_rows) - 1)
    first_formatted_row_in_writable_csv_rows_aux = writable_csv_rows_aux[0]
    timestamp_index = len(last_formatted_row_in_writable_csv_rows) - 1

    current_timestamp_string = last_formatted_row_in_writable_csv_rows[timestamp_index]
    next_timestamp_string    = first_formatted_row_in_writable_csv_rows_aux[timestamp_index]

    current_timestamp  = datetime.strptime(current_timestamp_string, '%Y-%m-%d %H:%M:%S')
    next_timestamp     = datetime.strptime(next_timestamp_string, '%Y-%m-%d %H:%M:%S')
    time_delta_in_secs = int((next_timestamp - current_timestamp).total_seconds()) - 1
    last_formatted_row_in_writable_csv_rows.append(time_delta_in_secs)

    writable_csv_rows_aux.insert(0, last_formatted_row_in_writable_csv_rows)

    with open(created_csv_file, "a") as csv_file:
        csv_writer = csv.writer(csv_file, csv.QUOTE_NONNUMERIC)
        for row in writable_csv_rows:
            csv_writer.writerow(row)
        for row in writable_csv_rows_aux:
            csv_writer.writerow(row)


def perform_queries_on(connection, json_map, file_type):
    connection_cursor  = connection.cursor()

    query  = """SELECT timestamp, host, COUNT(file_type) FROM pe_dumps WHERE file_type = '""" + file_type + \
                   """' AND host IS NOT NULL GROUP BY timestamp, host ORDER BY timestamp ASC"""

    connection_cursor.execute(query)
    for triple in connection_cursor:
        timestamp              = str(triple[0])
        timestamp_ymd          = timestamp.split()[0]
        host                   = triple[1]
        total_count_per_second = triple[2]

        json_map[timestamp_ymd][host] += total_count_per_second

    # query = """SELECT timestamp, COUNT(pe.file_type) FROM pe_dumps AS pe, amico_scores AS ams WHERE """ + \
    #                """pe.dump_id = ams.dump_id AND pe.file_type = '""" + file_type + """' AND ams.score > """  + \
    #                str(AMICO_THRESHOLD) + """ AND server = '""" + server + """' GROUP BY  timestamp ORDER """  +\
    #                """BY timestamp ASC"""
    #
    # connection_cursor.execute(query)
    # for tuple in connection_cursor:
    #     timestamp              = str(tuple[0])
    #     timestamp_ymd          = timestamp.split()[0]
    #     total_count_per_second = tuple[1]
    #
    #     if timestamp_ymd in malware_map:
    #         malware_map[timestamp_ymd] += total_count_per_second
    #     else:
    #         malware_map[timestamp_ymd] = total_count_per_second

    return total_map, malware_map

    # monitoring_server_ip                      = "127.0.0.1"
    # external_server_ip                        = server
    # # external_server_lat, external_server_lon = geolocalize_server(external_server_ip)
    # connection_cursor.execute(first_query)
    # for row in connection_cursor:
    #     if row is not None:
    #         timestamp = str(row[0])
    #         total_count_per_second = row[1]
    #
    #         dayID = timestamp.split()[0]



def generate_JSON_map_file():
    connection        = util.connect_to_db()
    json_map          = defaultdict(lambda: defaultdict(int))

    perform_queries_on(connection, json_map, "PDF")

# def test_graph_generation():
graph_id = MAP_GRAPH_ID
generate_graph(graph_id)