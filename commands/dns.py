# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import traceback
import re
import sys

from commands.basecommand import BaseCommand


class DNS(BaseCommand):
    def __init__(self):
        self.__name__ = 'DNS Cache'

    def run_ssh(self, sshc):
        data = self._ssh_data(sshc, '/ip dns print')
        enabled = 'allow-remote-requests: yes' in data.lower()

        res = self._ssh_data_with_header(sshc, '/ip dns cache print detail')
        sus_dns, recommendation = self.check_results_ssh(res, enabled)

        return {'raw_data': res,
                'suspicious': sus_dns,
                'recommendation': recommendation}

    def check_results_ssh(self, res, enabled):
        sus_dns = []
        recommendation = []

        try:
            for item in res:
                if self.calc_sec(item['ttl']) > 200000:
                    address_key = "address"
                    if "data" in item:
                        address_key = "data" #as seen in RouterOs 7.x

                    sus_dns.append(f'Domain name: {item["name"]} with ip {item[address_key]}: might be DNS poisoning - '
                                   f'severity: high')
        except Exception:
            print(traceback.format_exc(), file = sys.stderr)

        if enabled:
            recommendation.append('In case DNS cache is not required on your router - disable it')

        return sus_dns, recommendation

    def calc_sec(self, ttl):
        to_sec = {'s': 1, 'm': 60, 'h':3600, 'd':86400, 'w': 604800}
        time = re.findall(r"(\d+)([a-z])", ttl)
        return sum(list(map(lambda item: int(item[0]) * to_sec[item[1]], time)))








