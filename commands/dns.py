# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import re
from commands.basecommand import BaseCommand

def get_value(S, i):
    try:
        if S[i] == "" :
            return 0
        return int(S[i])
    except IndexError:
        return 0

def to_integer(dt_time):
    # code for parsing dt_time
    parse_list = re.split("[w,d,h,m,s]+",dt_time)
    return (get_value(parse_list,0)*7+get_value(parse_list,1))*1000000 + get_value(parse_list,2)*10000  +  get_value(parse_list,3)*100 + get_value(parse_list,4)

class DNS(BaseCommand):
    def __init__(self):
        self.__name__ = 'DNS Cache'

    def run_ssh(self, sshc):
        data = self._ssh_data(sshc, '/ip dns print')
        enabled = 'allow-remote-requests: yes' in data.lower()

        #res = self._ssh_data_with_header(sshc, '/ip dns cache print detail')
        res = self._ssh_data_with_header(sshc, '/ip dns cache print detail')
        sus_dns, recommendation = self.check_results_ssh(res, enabled)

        return {'raw_data': res,
                'suspicious': sus_dns,
                'recommendation': recommendation}

    def check_results_ssh(self, res, enabled):
        sus_dns = []
        recommendation = []

        for item in res:
            if to_integer(item['ttl'].partition('s')[0]) > 200000:
                sus_dns.append(f'Domain name: {item["name"]} with ip {item["data"]}: might be DNS poisoning- '
                               f'severity: high')

        if enabled:
            recommendation.append('In case DNS cache is not required on your router - disable it')

        return sus_dns, recommendation







