# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import traceback
import sys

from commands.basecommand import BaseCommand


class Users(BaseCommand):
    def __init__(self):
        self.__name__ = 'Users'

    def run_ssh(self, sshc):
        res = self._ssh_data_with_header(sshc, '/user print detail')
        sus_dns, recommendation = self.check_results_ssh(res)

        return {'raw_data': res,
                'suspicious': sus_dns,
                'recommendation': recommendation}

    def check_results_ssh(self, res):
        sus_users = []
        recommendation = []

        try:
            for item in res:
                if (item['name'] == 'admin') and (item['group'] == 'full'):
                    recommendation.append(
                        'You are using the default "admin" user name- create new user in "full" group with a unique name, '
                        'and delete the admin user')
                if item['address'] == '':
                    recommendation.append(f'Add allowed ip address to user: {item["name"]}, '
                                          f'to be the only address it can login from')
        except Exception:
            print(traceback.format_exc(), file = sys.stderr)

        return sus_users, recommendation







