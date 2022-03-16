# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from commands.basecommand import BaseCommand


class Proxy(BaseCommand):
    def __init__(self):
        self.__name__ = 'Proxy'

    def run_ssh(self, sshc):
        data = self._ssh_data(sshc, '/ip proxy print')
        enabled = 'enabled: yes' in data.lower()

        res = self._ssh_data_with_header(sshc, '/ip proxy access print detail')
        sus_dns, recommendation = self.check_results_ssh(res, enabled)

        return {'raw_data': res,
                'suspicious': sus_dns,
                'recommendation': recommendation}

    def check_results_ssh(self, res, enabled):
        sus_proxy = []
        recommendation = []

        if enabled:
            recommendation.append('Proxy detected. In case you don\'t need it - disable it')

        return sus_proxy, recommendation








