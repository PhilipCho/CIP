#!/usr/bin/env python3
import scipy.stats
import numpy
class AHP:
    def __init__(self, f12, f23, f13, s1 = 0, s2 = 0, s3 = 0):
        self._f12 = f12
        self._f23 = f23
        self._f13 = f13
        self._s1 = s1
        self._s2 = s2
        self._s3 = s3

    def calculate_relative_weights(self):
        self._weight_array = self.create_array()
        self._factor_1_gmean = scipy.stats.mstats.gmean(self._weight_array[0])
        self._factor_2_gmean = scipy.stats.mstats.gmean(self._weight_array[1])
        self._factor_3_gmean = scipy.stats.mstats.gmean(self._weight_array[2])
        total = self._factor_1_gmean + self._factor_2_gmean + self._factor_3_gmean
        self._f1_rank = self._factor_1_gmean/total
        self._f2_rank = self._factor_2_gmean/total
        self._f3_rank = self._factor_3_gmean/total
        return [self._f1_rank, self._f2_rank, self._f3_rank]

    def create_array(self):
        return [[1, self._f12, self._f13], [1/self._f12, 1, self._f23], [1/self._f13, 1/self._f23, 1]]

    def import_database_scores(self):
        #TODO: Link this with global database
        return None

    def calculate_unitless_weight(self):
        self._f1_unitless = self._f1_rank * self._s1
        self._f2_unitless = self._f2_rank * self._s2
        self._f3_unitless = self._f3_rank * self._s3
        self._total_unitless = self._f1_unitless + self._f2_unitless + self._f3_unitless
        return self._total_unitless

    def get_unitless_weight(self):
        self._calculate_relative_weights()
        return calculate_unitless_weight()


#only for testing
if __name__ == "__main__":
    test_ahp = AHP(2, 5, 7, 0.5, 0.5, 0.5)#1, 1, 0.1)
    #Error in paper: cyber maturity - second table is wrong
    a = test_ahp.get_unitless_weight()
    print(a)
