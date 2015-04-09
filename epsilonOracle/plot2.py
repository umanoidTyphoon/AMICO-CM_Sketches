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

errors = []
epsilons = []
features = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
            30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
            57, 58]

# Prepare data
for filename in os.listdir(epsilons_dir):
    if filename == ("0-domain_total_downloads.txt"):
        file_path = epsilons_dir + "/" + filename

        with open(file_path) as file:
            for line in file:
                splits = line.split(" ")
                # Extract error
                try:
                    error = float(splits[ERROR_POSITION_SPITTING_WITH_WHITESPACES])
                    int_error = int(error)
                    epsilon = float(splits[len(splits) - 1])
                    errors.append(int_error)
                    epsilons.append(epsilon)
                except ValueError:
                    # print "The string given in input is not a float..."
                    continue
        break

print(errors)
print(epsilons)

pos = np.arange(len(errors))
width = .5     # gives histogram aspect to the bar diagram

ax = plt.axes()
ax.set_xlabel("Error [%]")
ax.set_ylabel("epsilon")
ax.set_xticks(pos + (width / 2))
ax.set_xticklabels(errors)

plt.bar(pos, epsilons, width, color='#8cd3f1')
# plt.show()
plt.savefig(figures_dir + "/fixed_error_" + str(error_to_plot) + "_on_host_total.pdf", format='pdf', bbox_inches='tight')
