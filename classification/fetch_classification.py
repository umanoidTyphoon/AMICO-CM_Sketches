__author__ = 'vincenzo'

import util
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.mlab as mlab


values,mean,var,std = util.fetch_classification()

x = np.linspace(-1,1,100)
plt.plot(x,mlab.normpdf(x,mean,std))

plt.show()
