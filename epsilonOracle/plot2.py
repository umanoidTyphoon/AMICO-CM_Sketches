__author__ = 'Vincenzo Deriu'


import glob
import matplotlib.pyplot as plt
import numpy as np
import os
from matplotlib import rcParams
import sys

ERROR_POSITION_SPITTING_WITH_WHITESPACES = 3

width = 0.35       # the width of the bars

epsilons_dir = "./epsilons"
figures_dir  = "./figures"

# error_to_plot = int(sys.argv[1])
epsilons_dict = dict()
error_list = [0, 5, 10, 20]
width_dict = dict()

filename = ''
group_name = ''
n = 0

errors = []
epsilons = []
features = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
            30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
            57, 58]

# # Prepare data
# for filename in os.listdir(epsilons_dir):
#     if filename == ("0-domain_total_downloads.txt"):
#         file_path = epsilons_dir + "/" + filename
#
#         with open(file_path) as file:
#             for line in file:
#                 splits = line.split(" ")
#                 # Extract error
#                 try:
#                     error = float(splits[ERROR_POSITION_SPITTING_WITH_WHITESPACES])
#                     int_error = int(error)
#                     epsilon = float(splits[len(splits) - 1])
#                     errors.append(int_error)
#                     epsilons.append(epsilon)
#                 except ValueError:
#                     # print "The string given in input is not a float..."
#                     continue
#         break
#
# print(errors)
# print(epsilons)
#
# pos = np.arange(len(errors))
# width = .5     # gives histogram aspect to the bar diagram
#
# ax = plt.axes()
# ax.set_xlabel("Error [%]")
# ax.set_ylabel("epsilon")
# ax.set_xticks(pos + (width / 2))
# ax.set_xticklabels(errors)
#
# plt.bar(pos, epsilons, width, color='#8cd3f1')
# # plt.show()
# plt.savefig(figures_dir + "/fixed_error_" + str(error_to_plot) + "_on_host_total.pdf", format='pdf', bbox_inches='tight')


def sort_list_dir(filelist):
    sorted_listdir = []
    ordered_filenames = dict()

    for filename in filelist:
        if filename.endswith(".txt"):
            splits = filename.split("-")
            ordered_filenames[int(splits[0])] = "-" + splits[1]

    feature_ids = list(ordered_filenames)
    feature_ids = sorted(feature_ids)
    for ID in feature_ids:
        feature_name = ordered_filenames.get(ID)
        sorted_listdir.append((str(ID) + feature_name))
    # print sorted_listdir

    return sorted_listdir


def populate_dictionary(sorted_listdir, dictionary, error_to_be_extracted):
    found = 0
    for filename in sorted_listdir:
        feature_id = -1
        file_path = epsilons_dir + "/" + filename
        # print file_path

        with open(file_path) as file:
            for line in file:
                # print(line)
                splits = line.split(" ")
                # Extract error
                # print splits
                try:
                    error = float(splits[ERROR_POSITION_SPITTING_WITH_WHITESPACES])
                    int_error = int(error)
                    last_delimiter_index = file.name.rfind('/')
                    feature_name = file.name[last_delimiter_index + 1:]
                    feature_id = int(feature_name.split("-")[0])
                    # print feature_id
                    # print "Err: ", error
                    if int_error == error_to_be_extracted:
                        # Extract epsilon: it is contains in the last split
                        epsilon = float(splits[len(splits) - 1])
                        # print "Epsilon: ", epsilon
                        #if epsilon != 0.0:
                        # print epsilon
                        #error_epsilon.append(int_error)
                        #error_epsilon.append(epsilon)
                        #errors = np.append(errors, error)
                        epsilons_list = dictionary.get(int_error)
                        if epsilons_list == None:
                            epsilons_list = [epsilon]
                        else:
                            epsilons_list.append(epsilon)
                        dictionary[int_error] = epsilons_list
                        # print epsilons_dict, len(epsilons_dict.get(0))
                        found = 1
                        break
                    else:
                        continue

                except ValueError:
                    # print "The string given in input is not a float..."
                    continue
        epsilons_list = dictionary.get(error_to_be_extracted)
        if(found == 0):
            if epsilons_list is None:
                epsilons_list = [0.0]
                dictionary[error_to_be_extracted] = epsilons_list
            else:
                epsilons_list.append(0.0)
                dictionary[error_to_be_extracted] = epsilons_list
                # print epsilons_dict, len(epsilons_dict.get(0))
        else:
            found = 0

    # data[feature_id] = error_epsilon
    # print epsilons_dict, len(epsilons_dict.get(error_to_be_extracted))
    return dictionary


def compute_width_list(list):
    res = []
    for epsilon in list:
        if epsilon == 0.0:
            res.append(epsilon)
        else:
            width = int(np.ceil(np.exp(1) / epsilon))
            res.append(width)
    return res

# Compute width for the various sketches
sorted_listdir = sort_list_dir(os.listdir(epsilons_dir))
for error in error_list:
    epsilons_dict = populate_dictionary(sorted_listdir, epsilons_dict, error)
# print epsilons_dict

# for error in error_list:
#     epsilons_list = epsilons_dict.get(error)
#     width_list = compute_width_list(epsilons_list)
#     print width_list, len(width_list)

for error in error_list:
    epsilons_list = epsilons_dict.get(error)
    width_dict[error] = compute_width_list(epsilons_list)

width_list = width_dict.get(20)

pos = np.arange(len(features))
width = 1.0

ax = plt.axes()
ax.set_xlabel("Feature ID")
ax.set_ylabel("width")
ax.set_xticks(pos + (width / 2))
ax.set_xticklabels(sorted(list(features)))

plt.bar(pos, width_list, width, color='#8cd3f1')
plt.show()

