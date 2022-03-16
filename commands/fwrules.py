# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from commands.basecommand import BaseCommand


class FW(BaseCommand):
    def __init__(self):
        self.__name__ = 'FW Rules'

    def run_ssh(self, sshc):
        res = self._ssh_data_with_header(sshc, '/ip firewall filter print detail')

        return {'raw_data': res,
                'suspicious': [],
                'recommendation': []}








