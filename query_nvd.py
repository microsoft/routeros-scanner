# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import requests
import collections
import sys
from retry import retry


class NvdApiError(Exception):
    """Exception raised for errors in the API request """
    def __init__(self, params,  msg):
        self.message = f"Received an error during the API process with the following params: {params}. The API message: {msg}"
        super().__init__(self.message)

class hashabledict(dict):
    def __key(self):
        summ = []
        for k in sorted(self):
            v = self[k]
            if type(v) == dict:
                summ.append((k, hashabledict(v)))
            elif type(v) == list:
                summ.append((k, tuple(sorted(str(v)))))
            else:
                summ.append((k, v))
        return tuple(summ)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return self.__key() == other.__key()


class CVEsInterface():
    def __init__(self):
        self._ver_cves = collections.defaultdict(list)

    @retry((NvdApiError, Exception), tries=3, delay=2)
    def _web_api_query(self, url, params=None):
        response = requests.get(f"{url}", params=params, timeout=10)
        if response.status_code == 200:
            response = response.json()
            return response
        else:
            msg = ""
            if "message" in response.json().keys():
                msg = response.json()["message"]
            raise NvdApiError(params, msg)

    def nist_api(self, vendor, product):
        resultsPerPage = 500

        totalResults = self.get_cves(product, vendor, resultsPerPage, 0)

        for cur_index in range(resultsPerPage, totalResults, resultsPerPage):
            self.get_cves(product, vendor, resultsPerPage, cur_index)

        return self._ver_cves

    def get_cves(self, product, vendor, resultsPerPage, cur_index):
        total_results = 0
        response = self._web_api_query("https://services.nvd.nist.gov/rest/json/cves/1.0?",
                                       params={"keyword": product, "resultsPerPage": resultsPerPage,
                                               "startIndex": cur_index})
        if response:
            self._convert_to_ranges(response["result"]["CVE_Items"], vendor, product)
            total_results = response["totalResults"]
        return total_results

    def _convert_to_ranges(self, all_cves_data, vendor, product):
        for cve_data in all_cves_data:
            cve = cve_data["cve"]['CVE_data_meta']['ID']

            if cve in self._ver_cves.keys():
                continue

            if 'configurations' not in cve_data:
                print (f'ERROR: No configurations {cve}', file = sys.stderr)
            else:
                if 'nodes' not in cve_data['configurations']:
                    print (f'ERROR: No nodes {cve}', file = sys.stderr)
                else:
                    versions = []
                    for node in cve_data['configurations']['nodes']:
                        if node['operator'] != 'OR':
                            print(f'DEBUG: No handling for OR operator in node, the following CVE needs to be implemented: {cve}', file=sys.stderr)
                        else:
                            for cpe_match in node['cpe_match']:
                                cpe_res = hashabledict()
                                if 'cpe23Uri' in cpe_match:
                                    if not f'{vendor}:{product}' in cpe_match['cpe23Uri']:
                                        continue

                                if 'versionStartIncluding' in cpe_match:
                                    cpe_res['start_including'] = cpe_match['versionStartIncluding']
                                if 'versionEndIncluding' in cpe_match:
                                    cpe_res['end_including'] = cpe_match['versionEndIncluding']
                                if 'versionStartExcluding' in cpe_match:
                                    cpe_res['start_excluding'] = cpe_match['versionStartExcluding']
                                if 'versionEndExcluding' in cpe_match:
                                    cpe_res['end_excluding'] = cpe_match['versionEndExcluding']

                                if 'cpe23Uri' in cpe_match:
                                    exact_ver = cpe_match['cpe23Uri'].partition(f'cpe:2.3:o:{vendor}:{product}:')[2].partition(':')[0]
                                    if exact_ver not in (['*', '']):
                                        cpe_res['exact'] = exact_ver

                                if cpe_res:
                                    versions.append(cpe_res)
                    if versions:
                        self._ver_cves[cve] = list(set(versions))



