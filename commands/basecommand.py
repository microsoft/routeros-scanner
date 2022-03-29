# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import traceback
import sys


class BaseCommand(object):
    def _ssh_data(self, sshc, command):
        res = ''
        try:
            stdin, stdout, stderr = sshc.exec_command(command)
            res = str(stdout.read())
        except Exception:
            print(traceback.format_exc(), file = sys.stderr)

        return res

    def _ssh_data_with_header(self, sshc, command):
        data = self._ssh_data(sshc, command)
        res = []

        try:
            if ' 0 ' in data:
                res = data.partition(' 0 ')[2].split('\\r\\n\\r\\n')[:-1]
                res = list(map(lambda y: self._parse_data(y), res))
        except Exception:
            print(traceback.format_exc(), file = sys.stderr)

        return res

    def _parse_data(self, data):
        split_data = data.replace(' \\r\\n ', '').replace('\'', '').split('=')
        return dict(zip(list(map(lambda x: x.rpartition(' ')[-1].strip().replace('\"', ''), split_data[:-1])), \
                        list(map(lambda x: x.rpartition(' ')[0].strip().replace('\"', ''), \
                                 split_data[1:-1])) + [split_data[-1].strip().replace('\"', '')]))

    def run_ssh(self, data):
        raise NotImplementedError
