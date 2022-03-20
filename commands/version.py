# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from commands.basecommand import BaseCommand
from nvd import CVEValidator
import re


class Version(BaseCommand):
    def __init__(self):
        self.__name__ = 'Version'

    def run_ssh(self, sshc):
        version = ''
        res = ''
        data = self._ssh_data(sshc, '/system resource print')
        version_reg = re.search(r'version: ([\d\.]+)', data)

        if version_reg:
            version = version_reg.group(1)
            res = f'RouterOS version: {version}'

        sus_dns, recommendation = self.check_results_ssh(version)

        return {'raw_data': res,
                'suspicious': sus_dns,
                'recommendation': recommendation}

    def check_results_ssh(self, res):
        sus_version = []
        recommendation = []

        if res:
            cve = CVEValidator('./assets/mikrotik_cpe_match.json')
            ver_cves = cve.check_version(res)
            if ver_cves:
                sus_version = ver_cves

        return sus_version, recommendation



