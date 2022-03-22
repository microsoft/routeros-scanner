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

    def check_results_ssh(self, res, enabled):
        sus_dns = []
        recommendation = []

        # process the overall TTL string vs just the seconds as newer versions of fimrware show #d#h#m#s or some combination        
        for item in res:
            timetmp = item['ttl']

            # if time string is not just digits
            # convert it to seconds (as a string)
            if not timetmp.isdigit():
                #Convert to seconds
                timetmp = self.time_str_convert2sec(timetmp)

            # process seconds for validation
            if int(timetmp) > 200000:
                sus_dns.append(f'Domain name: {item["name"]} with ip {item["address"]}: might be DNS poisoning- '
                               f'severity: high')


        if enabled:
            recommendation.append('In case DNS cache is not required on your router - disable it')

        return sus_dns, recommendation




    # convert #d, #h, #m, #s to a count of seconds
    def convert_to_seconds(self, s):
        seconds_per_unit = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
        return int(s[:-1]) * seconds_per_unit[s[-1]]

    # split apart #d#h#m#s for use with above function
    # extra function so as not to repeat code
    def split_on_dhms(self, timestr, split, start):
        # split is d, h, m, s
        cut = timestr.find(split, start)
        
        # if found letter, 
        if cut > 0 :
            chunk = timestr[start:cut+1]
            seconds = self.convert_to_seconds(chunk)
            
            # if letter was there, return new start point and seconds found
            return cut+1, seconds
        
        # if letter wasn't there, return same starting point
        return start, 0
    
    
    # Handle timestrings in non second formats
    # ex time strings 1d1h44m8s
    # ex time strings 1d
    # ex time strings 1h44m8s
    # ex time strings 5m32s
    def time_str_convert2sec(self, timestr):
        start = 0
        seconds = 0
        sectmp = 0
        
        start, sectmp = self.split_on_dhms(timestr, 'd', start)
        seconds += sectmp

        start, sectmp = self.split_on_dhms(timestr, 'h', start)
        seconds += sectmp

        start, sectmp = self.split_on_dhms(timestr, 'm', start)
        seconds += sectmp

        start, sectmp = self.split_on_dhms(timestr, 's', start)
        seconds += sectmp
            
        return str(seconds)
