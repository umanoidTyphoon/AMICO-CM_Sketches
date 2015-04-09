__author__ = 'Vincenzo Deriu'

import sys
import random
import numpy as np

BIG_PRIME = 9223372036854775783

random_parameters = [[3855483969251045550, 8708688407112891618], [8926282854497893686, 4390665439843151325],
                     [2274948550203382259, 7360455785926943020], [7549048658687782964, 8145312472828294149],
                     [8086346051022946365, 8825528156902469898], [2254963801332704518, 2847806146481835937],
                     [3742599363140121417, 7810309941732699355], [4662970043116588076, 3995608470880119485],
                     [8127506216481886778, 2097246509310169464], [1164415423486499490, 947734926901625025],
                     [8992508990183509581, 238488925168692289],  [8596154617854201450, 4850723540680713533],
                     [6824159666599056129, 260263731934835712],  [3518190918593908304, 35867659355547039],
                     [1515839073414842035, 688270280519291225],  [597133351258255859, 7491907009982470321],
                     [3528950968555460028, 2179209161542291414], [353950969553360028, 2079208161542291414],
                     [3742666563140121417, 7816665941732699355], [3742666563140908304, 9083045941732699355],
                     [8086685051022946685, 6855528156906859898]]

# deltas for depth from 10 to 21
deltas = [10**-9, 10**-8.5, 10**-8, 10**-7.5, 10**-7, 10**-7, 10**-6.8, 10**-6.5, 10**-6, 10**-5.5, 10**-5, 10**-4.5,
          10**-4]


def random_parameter():
    return random.randrange(0, BIG_PRIME - 1)


class Sketch:
    def __init__(self, delta, epsilon, k, t):
        """
        Setup a new count-min sketch with parameters delta, epsilon, k and t

        The parameters delta,epsilon and k control the accuracy of the estimates of the sketch

        The parameter t defines if it's a counter with real or integer values (0=integer; 1=real)

        For an item i with count a_i, the estimate from the sketch a_i_hat will satisfy the relation

        a_hat_i <= a_i + epsilon * ||a||_1

        with probability at least 1 - delta, where a is the the vector of all
        all counts and ||x||_1 is the L1 norm of a vector x

        Parameters
        ----------
        delta : float
            A value in the unit interval that sets the precision of the sketch
        epsilon : float
            A value in the unit interval that sets the precision of the sketch
        k : int
            A positive integer that sets the size of the event window, i.e. the maximum number of past dump_id to
            consider

        Examples
        --------
        >>> s = Sketch(10**-7, 0.005, 10000)

        Raises
        ------
        ValueError
            If delta or epsilon are not in the unit interval, or if k is not a positive integer
        """
        if delta <= 0 or delta >= 1:
            raise ValueError("delta must be between 0 and 1, exclusive")
        if epsilon <= 0 or epsilon >= 1:
            print epsilon
            raise ValueError("epsilon must be between 0 and 1, exclusive")
        if k < 1:
            raise ValueError("k must be a positive integer")
        print
        self.w = int(np.ceil(np.exp(1) / epsilon))
        self.d = int(np.ceil(np.log(1 / delta)))
        self.k = k
        self.t = t
        self.hash_functions = []
        for i in range(self.d):
            self.hash_functions.append(self.__generate_hash_function(i))

        if t == 0:
            self.count = np.zeros((self.d, self.w), dtype='int32')
            size = self.w * self.d * 4 / 1024.0 / 1024.0
        else:
            if t == 1:
                self.count = np.zeros((self.d, self.w), dtype='float64')
                size = self.w * self.d * 8 / 1024.0 / 1024.0
            else:
                raise ValueError("Type must be 0 or 1")

        # print "SKETCH PARAMETERS:"
        # print
        # print "Delta = %.7f" %(delta,)
        # print "Epsilon = %7f" % (epsilon,)
        # print "Building a matrix %d X %d" % (self.w,self.d)
        # print "Matrix size : %3f MB" % (size,)
        # self.errMax = epsilon * k
        # print "Maximum expected error : %d\n" % (self.errMax,)

    def update(self, key, increment):
        """
            Updates the sketch for the item with name of key by the amount
            specified in increment

            Parameters
            ----------
            key : string
                The item to update the value of in the sketch
            increment : integer
                The amount to update the sketch by for the given key

            Examples
            --------
            >>> s = Sketch(10**-7, 0.005, 40)
            >>> s.update('http://www.cnn.com/', 1)

            """
        for row, hash_function in enumerate(self.hash_functions):
            column = hash_function(abs(hash(key)))
            self.count[row, column] += increment

    def get(self, key):
        """
        Fetches the sketch estimate for the given key

        Parameters
        ----------
        key : string
            The item to produce an estimate for

        Returns
        -------
        estimate : int
            The best estimate of the count for the given key based on the
            sketch

        Examples
        --------
        >>> s = Sketch(10**-7, 0.005, 40)
        >>> s.update('http://www.cnn.com/', 1)
        >>> s.get('http://www.cnn.com/')
        1

        """
        value = sys.maxint
        for row, hash_function in enumerate(self.hash_functions):
            column = hash_function(abs(hash(key)))
            value = min(self.count[row, column], value)

        return value

    def __generate_hash_function(self, iteration):
        """
        Returns a hash function from a family of pairwise-independent hash
        functions

        """
        a, b = random_parameters[iteration][0], random_parameters[iteration][1]
        # print "a: %d - b: %d" % (a, b)
        return lambda x: (a * x + b) % BIG_PRIME % self.w

    def get_type(self):
        return self.t

    def print_stats(self, type, out_file):
        size = 0
        if type == 0:
            size = self.w * self.d * 4 / 1024.0 / 1024.0
        else:
            if type == 1:
                size = self.w * self.d * 8 / 1024.0 / 1024.0
            else:
                raise ValueError("Type must be 0 or 1")
        out_file.write("Matrix %d X %d occupancy: %f MB\n" % (self.w, self.d, size))
