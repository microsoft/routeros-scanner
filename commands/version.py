# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import traceback
import re
import sys

from commands.basecommand import BaseCommand
from nvd import CVEValidator


class Version(BaseCommand):
    def __init__(self):
        self.__name__ = 'Version'

    def run_ssh(self, sshc):
        version = ''
        data = self._ssh_data(sshc, ':put [/system resource get version]')

        try:
            version_reg = re.search(r'([\d\.]+)', data)

            if version_reg:
                version = version_reg.group(1)
        except Exception:
            print(traceback.format_exc())

        sus, recommendation = self.check_results_ssh(version)

        return {'raw_data': version,
                'suspicious': sus,
                'recommendation': recommendation}

    def check_results_ssh(self, version):
        sus_version = []
        recommendation = []

        try:
            if version:
                cve = CVEValidator('./assets/mikrotik_cpe_match.json')
                ver_cves = cve.check_version(version)
                if ver_cves:
                    sus_version = ver_cves
                    recommendation.append(f'RouterOS version: {version} is vulnerable to CVE(s). Upgrade to the latest version.')
        except Exception:
            print(traceback.format_exc(), file = sys.stderr)

        return sus_version, recommendation



