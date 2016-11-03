#!/usr/bin/env python3
import math
from enum import Enum
import getcvssscore
class CVSS3:
    def __init__(self):
        self._initialized = True
        #self._scope = scope #0 - unchanged, 1 - changed

    def set_vector(self, attack_vector, attack_complexity, privilege_required, user_interaction, scope, impact_confidentiality, impact_integrity, impact_availability, exploit_code_maturity, remediation_level, report_confidence, confidentiality_requirement, integrity_requirement, availability_requirement):
        self.set_base(attack_vector, attack_complexity, privilege_required, user_interaction, scope, impact_confidentiality, impact_integrity, impact_availability)
        self.set_temporal(exploit_code_maturity, remediation_level, report_confidence)
        self.set_environmental(confidentiality_requirement, integrity_requirement, availability_requirement)

    def set_base(self,attack_vector, attack_complexity, privilege_required, user_interaction, scope, impact_confidentiality, impact_integrity, impact_availability):
        self._attack_vector = attack_vector
        self._attack_complexity = attack_complexity
        self._privilege_required = privilege_required
        self._user_interaction = user_interaction
        self._scope = scope
        self._impact_confidentiality = impact_confidentiality
        self._impact_integrity = impact_integrity
        self._impact_availability = impact_availability

    def set_temporal(self, exploit_code_maturity, remediation_level, report_confidence):
        self._exploit_code_maturity = exploit_code_maturity
        self._remediation_level = remediation_level
        self._report_confidence = report_confidence

    def set_environmental(self, confidentiality_requirement, integrity_requirement, availability_requirement):
        self._confidentiality_requirement = confidentiality_requirement
        self._integrity_requirement = integrity_requirement
        self._availability_requirement = availability_requirement

    def exploitability_subscore(self):
        self._ess =  8.22*self._attack_vector*self._attack_complexity*self._privilege_required*self._user_interaction
        return self._ess

    def iscbase(self):
        self._iscbase = 1-((1-self._impact_confidentiality)*(1-self._impact_integrity)*(1-self._impact_availability))

    def isc(self):
        self.iscbase()
        if self._scope:
            self._isc = (7.52*(self._iscbase-0.029)) - (3.25*((self._iscbase-0.02)**15))
        else:
            self._isc = 6.42*self._iscbase
        return self._isc

    def base(self):
        self.exploitability_subscore()
        self.isc()
        if self._isc <= 0:
            self._base = 0
        elif self._scope:
            self._base = round_tenth(min(1.08*(self._ess+self._isc),10))
        else:
            self._base = round_tenth(min((self._ess + self._isc),10))
        return self._base

    def temporal(self):
        self._temporal = round_tenth(self._base * self._exploit_code_maturity * self._remediation_level * self._report_confidence)
        return self._temporal

    def isc_modified(self):
        self._isc_modified = min((1-(1-self._impact_confidentiality * self._confidentiality_requirement) * (1-self._impact_integrity * self._integrity_requirement) * (1-self._impact_availability * self._availability_requirement)),0.915)
        return self._isc_modified

    def modified_exploitability_subscore(self):
        self._ess_modified = 8.22 * self._attack_vector * self._attack_complexity * self._privilege_required * self._user_interaction
        return self._ess_modified

    def impact_modified(self):
        self.isc_modified()
        if self._scope:
            self._impact_modified = 7.52*(self._isc_modified-0.029)-3.25*(self._isc_modified - 0.02)*15
        else:
            self._impact_modified = 6.42*self._isc_modified
        return self._impact_modified

    def environmental(self):
        self.impact_modified()
        self.modified_exploitability_subscore()
        if self._isc_modified <= 0:
            self._environmental = 0
        elif self._scope:
            self._environmental = round_tenth(round_tenth(min(1.08*(self._impact_modified+self._ess_modified)*self._exploit_code_maturity*self._remediation_level*self._report_confidence),10))
        else:
            self._environmental = round_tenth(round_tenth(
            min(((self._impact_modified+self._ess_modified) * self._exploit_code_maturity * self._remediation_level * self._report_confidence),10)))
        return self._environmental

class CVSS2:
    def __init__(self):
        self._initialized = True

    def set_vector(self):
        return None

    def set_vector(self, confidentiality_impact, integrity_impact, availability_impact, access_complexity, authentication, access_vector, exploitability, remediation_level, report_confidence, collateral_damage, target_distribution, confidentiality_requirement, integrity_requirement, availability_requirement):
        self.set_base(confidentiality_impact, integrity_impact, availability_impact, access_complexity, authentication, access_vector)
        self.set_temporal(exploitability, remediation_level, report_confidence)
        self.set_environmental(collateral_damage, target_distribution, confidentiality_requirement, integrity_requirement, availability_requirement)

    def set_base(self, confidentiality_impact, integrity_impact, availability_impact, access_complexity, authentication, access_vector):
        self._confidentiality_impact = confidentiality_impact
        self._integrity_impact = integrity_impact
        self._availability_impact = availability_impact
        self._access_complexity = access_complexity
        self._authentication = authentication
        self._access_vector = access_vector

    def set_temporal(self, exploitability, remediation_level, report_confidence):
        self._exploitability = exploitability
        self._remediation_level = remediation_level
        self._report_confidence = report_confidence

    def set_environmental(self, collateral_damage, target_distribution, confidentiality_requirement, integrity_requirement, availability_requirement):
        self._collateral_damage = collateral_damage
        self._target_distribution = target_distribution
        self._confidentiality_requirement = confidentiality_requirement
        self._integrity_requirement = integrity_requirement
        self._availability_requirement = availability_requirement

    def base(self):
        self._impact = 10.41 * (1 - ((1 - self._confidentiality_impact) * (1 - self._integrity_impact) * (1 - self._availability_impact)))
        self._ess = 20 * self._access_complexity * self._authentication * self._access_vector
        fImpact = 0.0
        if self._impact:
            fImpact = 1.176
        self._base = ((0.6 * self._impact) + (0.4 * self._ess) - 1.5) * fImpact
        return self._base

    def temporal(self):
        self._temporal = self._base * self._exploitability * self._remediation_level * self._report_confidence
        return self._temporal

    def environmental(self):
        self._adjusted_impact = min(10, 10.41*(1-((1 - (self._confidentiality_impact * self._confidentiality_requirement))*(1 - (self._integrity_impact * self._integrity_requirement))*(1 - (self._availability_impact * self._availability_requirement)))))
        fImpact = 0
        if self._adjusted_impact:
            fImpact = 1.176
        self._adjusted_base = ((0.6 * self._adjusted_impact) + (0.4 * self._ess) - 1.5)*fImpact
        self._adjusted_temporal = self._adjusted_base * self._exploitability * self._remediation_level * self._report_confidence
        self._environmental = (self._adjusted_temporal + ((10 - self._adjusted_temporal) * self._collateral_damage)) * self._target_distribution
        return self._environmental

def round_tenth(num):
    return math.ceil(num*10)/float(10)

class CVSS3Constant(Enum):
    #base
    #Attack Vector
    AVN = 0.85
    AVA = 0.62
    AVL = 0.55
    AVP = 0.20
    #Attack Complexity
    ACL = 0.77
    ACH = 0.44
    #Privileges Required
    PRN = 0.85
    PRLC = 0.68
    PRHC = 0.50
    PRLU = 0.62
    PRHU = 0.27
    #User Interaction
    UIN = 0.85
    UIR = 0.62
    #Impact Metrics
    CN = 0.56
    CL = 0.22
    CH = 0.00
    IN = 0.56
    IL = 0.22
    IH = 0.00
    AN = 0.56
    AL = 0.22
    AH = 0.00
    #Exploitability
    EX = 1.00
    EU = 0.91
    EP = 0.94
    EF = 0.97
    EH = 1.00
    #Remediation Level
    RLX = 1.00
    RLO = 0.95
    RLT = 0.96
    RLW = 0.97
    RLU = 1.00
    #Report Confidence
    RCX = 1.00
    RCU = 0.92
    RCR = 0.96
    RCC = 1.00
    #Environmental Attack Vector
    MAVX = 0.00
    MAVN = 0.85
    MAVA = 0.62
    MAVL = 0.55
    MAVP = 0.20
    #Environmental Attack Complexity
    MACX = 0.00
    MACL = 0.77
    MACH = 0.44
    #Environmental Privileges Required
    MPRX = 0.00
    MPRN = 0.85
    MPRLC = 0.68
    MPRHC = 0.50
    MPRLU = 0.62
    MPRHU = 0.27
    #Environmental User Interaction
    MUIX = 0.00
    MUIN = 0.85
    MUIR = 0.62
    #Environmental Scope
    MSX = 0.00
    MSU = 0.00
    MSC = 1.00
    #Environmental Confidentiality Impact
    MCX = 0.00
    MCN = 0.00
    MCL = 0.22
    MCH = 0.56
    #Environmental Integrity Impact
    MIX = 0.00
    MIN = 0.00
    MIL = 0.22
    MIH = 0.56
    #Environmental Availability Impact
    MAX = 0.00
    MAN = 0.00
    MAL = 0.22
    MAH = 0.56
    #Confidentiality Requirement
    CRX = 1.00
    CRL = 0.50
    CRM = 1.00
    CRH = 1.50
    #Integrity Requirement
    IRX = 1.00
    IRL = 0.50
    IRM = 1.00
    IRH = 1.50
    #Availability Requirement
    ARX = 1.00
    ARL = 0.50
    ARM = 1.00
    ARH = 1.50

class CVSS2Constant(Enum):
    #Access Vector
    AVL = 0.395
    AVA = 0.646
    AVN = 1.000
    #Access Complexity
    ACH = 0.35
    ACM = 0.61
    ACL = 0.71
    #Authentication
    AUM = 0.704
    AUS = 0.56
    AUN = 0.45
    #Confidentiality Impact
    CN = 0.000
    CP = 0.275
    CC = 0.660
    #Integrity Impact
    IN = 0.000
    IP = 0.275
    IC = 0.660
    #Availability Impact
    AN = 0.000
    AP = 0.275
    AC = 0.660
    #Exploitability
    END =  1.00
    EU =   0.85
    EPOC = 0.90
    EF =   0.95
    EH =   1.00
    #Remediation Level
    RLND = 1.00
    RLOF = 0.87
    RLTF = 0.90
    RLW =  0.95
    RLU =  1.00
    #Report Confidence
    RCND = 1.00
    RCUC = 0.90
    RCUR = 0.95
    RCC =  1.00
    #Collatoral Damage Potential
    CDPND = 0.0
    CDPN =  0.0
    CDPL =  0.1
    CDPLM = 0.3
    CDPMH = 0.4
    CDPH =  0.5
    #Target Distribution
    TDND = 1.00
    TDN =  0.00
    TDL =  0.25
    TDM =  0.75
    TDH =  1.00
    #Confidentiality Requirement
    CRND = 1.00
    CRL =  0.50
    CRM =  1.00
    CRH =  1.51
    #Integrity Requirement
    IRND = 1.00
    IRL =  0.50
    IRM =  1.00
    IRH =  1.51
    #Availability Requirement
    ARND = 1.00
    ARL =  0.50
    ARM =  1.00
    ARH =  1.51

if __name__=="__main__":
    cvss = CVSS3()
    cvss.set_vector(.85, .77, .62, .62, 0, .56, .56, .56, 1.0, 1.0, .96, 1.0, 1.0, 1.0)
    #cvss.set_base(.85, .77, .62, .62, 0, .56, .56, .56)
        #network, low, low, required, unchanged, hi, hi, hi
        #attack_vector, attack_complexity, privilege_required, user_interaction, scope, impact_confidentiality, impact_integrity, impact_availability)
    a = cvss.base()
    #cvss.set_temporal(float(1), float(1), .96)
    b = cvss.temporal()
        #high, unavailable, reasonable
    #cvss.set_environmental(1.0, 1.0, 1.0)#, 1.0, 1.5)
    c = cvss.environmental()
        #low, med, high
    print(a)
    print(b)
    print(c)
    cvss2 = CVSS2()
    cvss2.set_base(0.660, 0.275, 0.660, 0.71, 0.56, 0.646)
        #complete, partial, complete, low, single, adjacent
    d = cvss2.base()
    cvss2.set_temporal(0.95, 0.95, 0.9)
        #functional, work-around, unconfirmed
    e = cvss2.temporal()
    cvss2.set_environmental(0.5, 0.75, 0.5, 1.0, 1.51)
        #high, medium, low, medium, high
    f = cvss2.environmental()
    print(d)
    print(e)
    print(f)
    #cvss.isc()
    #print(min(5,10))
