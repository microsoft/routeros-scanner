# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from commands.basecommand import BaseCommand
from util.parse_ttl import parse_ttl

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

        for item in res:
            item['parsed_ttl'] = parse_ttl(item['ttl'])
            if item['parsed_ttl'] > 200000:
                sus_dns.append(f'Domain name: {item["name"]} with ip {item["address"]}: might be DNS poisoning- '
                               f'severity: high')

        if enabled:
            recommendation.append('In case DNS cache is not required on your router - disable it')

        return sus_dns, recommendation







