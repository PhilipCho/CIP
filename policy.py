#!/usr/bin/env python3

class PolicyRisk:
    def __init__(self, cn, tm, uptime, hon, hgt):
        self._cn = cn
        self._tm = tm
        self._uptime = uptime
        self._hon = hon
        self._hgt = hgt
        self._risk = max((float(cn)/tn)*hgt, (float(hon)/uptime)*10)

    def risk(self):
        return self._risk
