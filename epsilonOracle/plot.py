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

error_to_plot = int(sys.argv[1])

filename = ''
group_name = ''
n = 0

data = {}
epsilons = []
errors = np.array([])
features = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
            30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
            57, 58]

# Prepare data
for filename in os.listdir(epsilons_dir):
    if filename.endswith(".txt"):
        feature_id = -1
        file_path = epsilons_dir + "/" + filename
        error_epsilon = []
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
                    if int_error >= error_to_plot:
                        # print error
                        # Extract epsilon: it is contains in the last split
                        epsilon = float(splits[len(splits) - 1])
                        # print "Epsilon: ", epsilon
                        if epsilon != 0.0:
                            # print epsilon
                            error_epsilon.append(int_error)
                            error_epsilon.append(epsilon)
                            errors = np.append(errors, error)
                        break
                except ValueError:
                    # print "The string given in input is not a float..."
                    continue
        data[feature_id] = error_epsilon

# TODO! Da controllare...
data.pop(-1, None)
print data
# print errors

keys = list(data)
keys = sorted(keys)
# print keys

# # Draw all features
# zero_counter = 0
# for key in keys:
#     error_epsilon_pair = data.get(key)
#     # print key, error_epsilon_pair
#     # The pair is not empty
#     if error_epsilon_pair:
#         epsilons.append(error_epsilon_pair[1])
#     else:
#         zero_counter += 1
#         epsilons.append(0.0)
# # print epsilons
# # print "Elements equal to 0: %d" % zero_counter
# # print len(epsilons)
#
# pos = np.arange(len(features))
# width = 1.0     # gives histogram aspect to the bar diagram
#
# ax = plt.axes()
# ax.set_xlabel("Feature ID")
# ax.set_ylabel("epsilon")
# ax.set_xticks(pos + (width / 2))
# ax.set_xticklabels(features)
#
# plt.bar(pos, epsilons, width, color='#8cd3f1')
# # plt.show()
#
# plt.savefig(figures_dir + "/features-" + str(error_to_plot) + "error.pdf", format='pdf', bbox_inches='tight')

epsilons = []

# Draw features with the error greater equal than the one given in inputs
features_with_error_to_plot = []

for index in range(len(features)):
    error_epsilon_pair = data.get(index)
    if error_epsilon_pair:
        features_with_error_to_plot.append(index)
        epsilons.append(error_epsilon_pair[1])
# print features_with_error_to_plot
# print epsilons

# pos2 = np.arange(len(features_with_error_to_plot))
# width = 1.0     # gives histogram aspect to the bar diagram
#
# ax2 = plt.axes()
# ax2.set_xlabel("Feature ID")
# ax2.set_ylabel("epsilon")
# ax2.set_xticks(pos2 + (width / 2))
# ax2.set_xticklabels(sorted(list(features_with_error_to_plot)))
#
# plt.bar(pos2, epsilons, width, color='#8cd3f1')
# plt.show()
# plt.savefig(figures_dir + "/features-only" + str(error_to_plot) + "error.pdf", format='pdf', bbox_inches='tight')


# Draw features with the error less than the one given in inputs
features_with_error = {}
features_with_error[5]  = [2.111361, 0.453047]
features_with_error[14] = [5.263158, 0.339785]
features_with_error[17] = [2.067982, 0.388326]
features_with_error[19] = [7.909921, 0.27182832]
features_with_error[31] = [4.860343, 0.453047]
features_with_error[48] = [9.013701, 0.030203]
features_with_error[55] = [7.692308, 0.271828]

epsilons = [0.453047, 0.339785, 0.388326, 0.27182832, 0.453047, 0.030203, 0.271828]

features_with_error2 = {}
features_with_error2[2]  = [10.526316, 0.453047]
features_with_error2[5]  = [13.111361, 0.543656]
features_with_error2[6]  = [17.815921, 0.041820]
features_with_error2[7]  = [10.468935, 0.339785]
features_with_error2[11] = [19.360756, 0.015622]
features_with_error2[14] = [15.263158, 0.339785]
features_with_error2[15] = [18.659898, 0.049423]
features_with_error2[17] = [19.067982, 0.388326]
features_with_error2[18] = [19.427597, 0.046073]
features_with_error2[19] = [7.909921, 0.302031]
features_with_error2[23] = [19.836842, 0.015713]
features_with_error2[26] = [10.526316, 0.339785]
features_with_error2[29] = [11.000000, 0.453047]
features_with_error2[30] = [19.552970, 0.048541]
features_with_error2[31] = [4.860343, 0.453047]
features_with_error2[39] = [19.940171, 0.044562]
features_with_error2[41] = [10.872576, 0.543656]
features_with_error2[42] = [17.803011, 0.042473]
features_with_error2[50] = [17.7213797707, 0.00226523485705]
features_with_error2[53] = [19.21875, 0.00151015657137]
features_with_error2[55] = [7.692308, 0.271828]

epsilons = [0.453047, 0.339785, 0.388326, 0.27182832, 0.453047, 0.030203, 0.271828]

# print features_with_error
# pos3 = np.arange(len(features_with_error))
# width = .5     # gives histogram aspect to the bar diagram
#
# ax3 = plt.axes()
# ax3.set_xlabel("Feature ID")
# ax3.set_ylabel("epsilon")
# ax3.set_xticks(pos3 + (width / 2))
# ax3.set_xticklabels(sorted(list(features_with_error)))
#
# # print sorted(list(features_with_error))
#
# plt.bar(pos3, epsilons, width, color='#8cd3f1')
# # plt.show()

# plt.savefig(figures_dir + "/features-less" + str(error_to_plot) + "error.pdf", format='pdf', bbox_inches='tight')


for key, error_epsilon_pair in features_with_error2.iteritems():
    errors = np.append(errors, error_epsilon_pair[0])

for zero_error in range(len(features) - len(errors)):
    errors = np.append(errors, 0.0)

print errors
# print len(errors)
print "Mean error over all the features: %f" % np.mean(errors)

# for dir in dirs:
#     error_rate = []
#     variance_rate =[]
#     labels = []
#
#     group_name = dir
#     files = glob.glob(dir+'/*.out')
#     n = len(files)
#
#     for file in files:
#         f=open(file, 'r')
#         lines = f.readlines()[9:]
#         i = 0
#         for line in lines:
#             value = line[line.rindex(":")+2:]
#             if i==0 :
#                 error_rate.append(float(value))
#                 i += 1
#             else:
#                 variance_rate.append(float(value))
#                 i = 0
#         filename = f.name[f.name.rindex("/")+1:f.name.find(".")]
#         labels.append(filename)
#         f.close()
#
#     fig, ax = plt.subplots()
#     ind = np.arange(n)  # the x locations for the groups
#
#     rects1 = ax.bar(ind, error_rate, width, color='r')
#     rects2 = ax.bar(ind+width, variance_rate, width, color='y')
#
#
#     ax.set_ylabel('Value %')
#     ax.set_title(group_name[group_name.find("output/")+7:])
#     ax.set_xticks(ind+width)
#     ax.set_xticklabels( labels, rotation='vertical')
#     lgd = ax.legend( (rects1[0], rects2[0]), ('Error', 'Variance'), loc='upper left', bbox_to_anchor=(1, 0.5) )
#
#     #plt.show()
#     plt.savefig(pathFigures+group_name[group_name.rfind('/'):]+"_out.pdf", format='pdf', bbox_extra_artists=(lgd,), bbox_inches='tight')
