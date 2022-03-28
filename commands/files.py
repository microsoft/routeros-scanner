# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import traceback
import sys

from commands.basecommand import BaseCommand


class Files(BaseCommand):
    def __init__(self):
        self.__name__ = 'Files'

    def run_ssh(self, sshc):
        res = self._ssh_data_with_header(sshc, '/file print detail')
        sus_dns, recommendation = self.check_results_ssh(res)

        return {'raw_data': res,
                'suspicious': sus_dns,
                'recommendation': recommendation}

    def check_results_ssh(self, res):
        sus_files = []
        recommendation = []

        try:
            for item in res:
                if 'contents' in item:
                    if ('/tool fetch' in item['contents']) or ('http://' in item['contents']):
                        sus_files.append(f'File name: {item["name"]}, content: {item["contents"]} - severity: high')
        except Exception:
            print(traceback.format_exc(), file = sys.stderr)

        return sus_files, recommendation





