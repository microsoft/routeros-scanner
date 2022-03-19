# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from commands.basecommand import BaseCommand


class DNS(BaseCommand):
    def __init__(self):
        self.__name__ = 'DNS Cache'

    def run_ssh(self, sshc):
        data = self._ssh_data(sshc, '/ip dns print')
        enabled = 'allow-remote-requests: yes' in data.lower()

        res = self._ssh_data_with_header(sshc, '/ip dns cache print detail')
        sus_dns, recommendation = self.check_results_ssh(res, enabled)

        return {'raw_data': res,
                'suspicious': sus_dns,
                'recommendation': recommendation}


    def __time_to_seconds(self, item):
            ttl = item['ttl']
            total_seconds = 0
            _ = ttl
            if 'd' in _:
                days, _ = _.split('d')
                total_seconds += int(days) * 86400 
            if 'h' in _:
                hours, _ = _.split('h')
                total_seconds +=  int(hours) * 3600
            if 'm' in _:
                minutes, _ = _.split('m')
                total_seconds +=  int(minutes) * 60
            if 's' in _:
                seconds, _ = _.split('s')
                total_seconds +=  int(seconds)
            return total_seconds
        
    def check_results_ssh(self, res, enabled):
        sus_dns = []
        recommendation = []

        for item in res:
            seconds = self.__time_to_seconds(item)
            
            if  "address" not in item:
                item['address'] = item.get("data")
            
            if not item.get("name",""):
                item["name"] = item.get("data")
                
            if seconds> 200000:                
                sus_dns.append(f'Domain name: {item["name"]} with ip {item["address"]}: might be DNS poisoning- '
                               f'severity: high')

        if enabled:
            recommendation.append('In case DNS cache is not required on your router - disable it')

        return sus_dns, recommendation







