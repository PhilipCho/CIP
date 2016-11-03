#!/usr/bin/env python3

class InsiderRisk:
    def __init__(self, hgt, tuad, tua):
        self._hgt = hgt
        self._tuad = tuad
        self._tua = tua
        self._risk = (float(tuad)/tua)*hgt

    def risk(self):
        return self._risk
