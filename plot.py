__author__ = 'Vincenzo Deriu'


import numpy as np
import matplotlib.pyplot as plt
import glob
from matplotlib import rcParams







width = 0.35       # the width of the bars

path = '/home/vincenzo/amico/count_min_sketches/output/*'
dirs = glob.glob(path)

filename = ''
group_name = ''
n = 0

for dir in dirs:
    error_rate = []
    variance_rate =[]
    labels = []

    group_name = dir
    files = glob.glob(dir+'/*.out')
    n = len(files)

    for file in files:
        f=open(file, 'r')
        lines = f.readlines()[9:]
        i = 0
        for line in lines:
            value = line[line.rindex(":")+2:]
            if i==0 :
                error_rate.append(float(value))
                i += 1
            else:
                variance_rate.append(float(value))
                i = 0
        filename = f.name[f.name.rindex("/")+1:f.name.find(".")]
        labels.append(filename)
        f.close()

    fig, ax = plt.subplots()
    ind = np.arange(n)  # the x locations for the groups

    rects1 = ax.bar(ind, error_rate, width, color='r', yerr=variance_rate)



    ax.set_ylabel('Value %')
    ax.set_title(group_name[group_name.find("output/")+7:])
    ax.set_xticks(ind+width)
    ax.set_xticklabels( labels, rotation='vertical')

    #lgd = ax.legend( (rects1[0], rects2[0]), ('Error', 'Variance'), loc='upper left', bbox_to_anchor=(1, 0.5) )

    #plt.show()
    plt.savefig(group_name+"_out.pdf", format='pdf', bbox_inches='tight')
