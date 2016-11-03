#!/usr/bin/env python3

class SBRM:
    def __init__(self, device_list):
        self._device_list = device_list
        self._initialized = True

    def calc_sbrm(self):
        sbrm = 0
        for device in self._device_list:
            subtotal = 1
            for vulnerability in device.vulnerabilities():
                subtotal = subtotal * (1-((vulnerability/10)**2))
            sbrm = sbrm + (device.weight()*(1-subtotal))
        self._sbrm = sbrm
        return self._sbrm

class Device:
    def __init__(self, vuln_vector, device_weight): #vuln_vector is a list of cvss scores
        self._vulnerabilities = vuln_vector
        self._device_weight = device_weight

    def vulnerabilities(self):
        return self._vulnerabilities

    def weight(self):
        return self._device_weight
