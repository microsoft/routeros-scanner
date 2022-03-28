# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import traceback
from ipaddress import ip_address
import sys

from commands.basecommand import BaseCommand


class FWNat(BaseCommand):
    def __init__(self):
        self.__name__ = 'FW Nat'

    def run_ssh(self, sshc):
        res = self._ssh_data_with_header(sshc, '/ip firewall nat print detail')
        sus_dns, recommendation = self.check_results_ssh(res)

        return {'raw_data': res,
                'suspicious': sus_dns,
                'recommendation': recommendation}

    def check_results_ssh(self, res):
        sus_nat = []
        recommendation = []

        try:
            for item in res:
                if (item['action'] == 'dst-nat') and ('dst-address' in item) and ('to-address' in item):
                    if (not ip_address(item['dst-address']).is_private) and (not ip_address(item['to-address']).is_private):
                        sus_nat.append(f'dst-nat rule from {item["dst-address"]} to {item["to-address"]}: both are public '
                                       f'IPs, might used for malicious activity - severity: high')
        except Exception:
            print(traceback.format_exc(), file = sys.stderr)

        return sus_nat, recommendation









