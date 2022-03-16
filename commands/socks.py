# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from commands.basecommand import BaseCommand


class Socks(BaseCommand):
    def __init__(self):
        self.__name__ = 'Socks'

    def run_ssh(self, sshc):
        data = self._ssh_data(sshc, '/ip socks print')
        enabled = 'enabled: yes' in data.lower()

        res = self._ssh_data_with_header(sshc, '/ip socks access print detail')
        sus_dns, recommendation = self.check_results_ssh(res, enabled)

        return {'raw_data': res,
                'suspicious': sus_dns,
                'recommendation': recommendation}

    def check_results_ssh(self, res, enabled):
        sus_socks = []
        recommendation = []

        if enabled:
            recommendation.append('Socks detected. In case you don\'t need it - disable it')

        return sus_socks, recommendation




