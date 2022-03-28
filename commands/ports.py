# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import traceback
import sys

from commands.basecommand import BaseCommand


class Ports(BaseCommand):
    def __init__(self):
        self.__name__ = 'Ports'

    def run_ssh(self, sshc):
        res = self._ssh_data_with_header(sshc, '/ip service print detail')
        sus_dns, recommendation = self.check_results_ssh(res)

        return {'raw_data': res,
                'suspicious': sus_dns,
                'recommendation': recommendation}

    def check_results_ssh(self, res):
        sus_ports = []
        recommendation = []
        def_ports = {'telnet': 23, 'ftp': 21, 'www': 80, 'ssh': 22, 'www-ssl': 443, 'api': 8728, 'winbox': 8291,
                     'api-ssl': 8729}

        try:
            for item in res:
                service = item['name']
                if def_ports[service] != int(item['port']):
                    sus_ports.append(f'The port for {service}, has changed from {def_ports[service]} to {item["port"]} - '
                                     f'severity: low')

                if (service == 'ssh') and (int(item['port']) == 22):
                    recommendation.append('The port for ssh protocol is as ssh default port (22)- Mikrotik company '
                                          'recommended to change it')
        except Exception:
            print(traceback.format_exc(), file = sys.stderr)

        return sus_ports, recommendation










