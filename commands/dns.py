# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time
import re

from commands.basecommand import BaseCommand

class DNS(BaseCommand):
    def __init__(self):
        self.rx = re.compile('(\d+d)?(\d+h)?(\d+m)?(\d+s)?')
        self.__name__ = 'DNS Cache'

    def get_seconds(self, ttl):
        groups = self.rx.match(ttl).groups()
        d=0 if not groups[0] else int(groups[0][:-1])
        h=0 if not groups[1] else int(groups[1][:-1])
        m=0 if not groups[2] else int(groups[2][:-1])
        s=0 if not groups[3] else int(groups[3][:-1])
        h=h+(d*24)
        s=s+(m*60)+(h*3600)
        return s

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
            if self.get_seconds(item['ttl']) > 200000:
                sus_dns.append(f'Domain name: {item["name"]} with ip {item["data"]}: might be DNS poisoning- '
                               f'severity: high')

        if enabled:
            recommendation.append('In case DNS cache is not required on your router - disable it')

        return sus_dns, recommendation