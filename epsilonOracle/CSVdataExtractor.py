__author__ = 'umanoidTyphoon'

import matplotlib.pyplot as plt
import numpy as np
import os
import sys

ERROR_POSITION_SPITTING_WITH_WHITESPACES = 3
PERCENTAGE_ERROR_UNDER_ANALYSIS = 10

width = 0.35       # the width of the bars

epsilons_dir = "./epsilons"
figures_dir  = "./figures"

error_to_plot = PERCENTAGE_ERROR_UNDER_ANALYSIS

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
# print data
# print errors

keys = list(data)
keys = sorted(keys)
# print keys

epsilons = []

# Draw features with the error greater equal than the one given in inputs
features_with_error_to_plot = []

for index in range(len(features)):
    error_epsilon_pair = data.get(index)
    if error_epsilon_pair:
        features_with_error_to_plot.append(index)
        epsilons.append(error_epsilon_pair[1])
#print features_with_error_to_plot
#print epsilons

i = 0
print "FEATURE ID,EPSILON"
for ID in features_with_error_to_plot:
    print "%d,%f" % (ID, epsilons[i])
    i += 1