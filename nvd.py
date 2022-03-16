# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json

class Comparison(object):
    SMALLER = -1
    SAME = 0
    BIGGER = 1
    

class CVEValidator(object):
    def __init__(self, jsonfname):
        with open(jsonfname, 'r') as fjson:
            self._all_cpe_match_data = json.loads(fjson.read())
    
    def _compare_3_section_version(self, version, version_to_compare_to):
        va_splitted = version.split('.')
        vb_splitted = version_to_compare_to.split('.')
        
        comparison = Comparison.SAME
        
        for index in range(3):
            a = 0
            
            if len(va_splitted) > index:
                a = int(va_splitted[index])
                
            b = 0
            
            if len(vb_splitted) > index:
                b = int(vb_splitted[index])
            
            if a == b:
                continue
            elif a < b:
                comparison = Comparison.SMALLER
                break
            else:
                comparison = Comparison.BIGGER
                break
                
        return comparison
    
    def check_version(self, version):
        res = []
        
        for cve in self._all_cpe_match_data:
            for match_ranges in self._all_cpe_match_data[cve]:
                if 'start_including' in match_ranges:
                    if self._compare_3_section_version(version, \
                                                       match_ranges['start_including']) >= Comparison.SAME:
                        if 'end_including' in match_ranges:
                            if self._compare_3_section_version(version, \
                                                       match_ranges['end_including']) <= Comparison.SAME:
                                res.append(cve)
                        elif 'end_excluding' in match_ranges:
                            if self._compare_3_section_version(version, \
                                                       match_ranges['end_excluding']) < Comparison.SAME:
                                res.append(cve)
                        else:
                            res.append(cve)
                elif 'end_including' in match_ranges:
                    if self._compare_3_section_version(version, \
                                               match_ranges['end_including']) <= Comparison.SAME:
                        res.append(cve)
                elif 'start_excluding' in match_ranges:
                    if self._compare_3_section_version(version, \
                                                       match_ranges['start_excluding']) > Comparison.SAME:
                        if 'end_including' in match_ranges:
                            if self._compare_3_section_version(version, \
                                                       match_ranges['end_including']) <= Comparison.SAME:
                                res.append(cve)
                        elif 'end_excluding' in match_ranges:
                            if self._compare_3_section_version(version, \
                                                       match_ranges['end_excluding']) < Comparison.SAME:
                                res.append(cve)
                        else:
                            res.append(cve)
                elif 'end_excluding' in match_ranges:
                    if self._compare_3_section_version(version, \
                                               match_ranges['end_excluding']) < Comparison.SAME:
                        res.append(cve)
                elif 'exact' in match_ranges:
                    if self._compare_3_section_version(version, \
                                               match_ranges['exact']) == Comparison.SAME:
                        res.append(cve)
                        
        return list(set(res))