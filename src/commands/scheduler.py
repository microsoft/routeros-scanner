from commands.basecommand import BaseCommand
import re


class Scheduler(BaseCommand):
    def __init__(self):
        self.__name__ = 'Scheduler'

    def run_ssh(self, sshc):
        res = self._ssh_data_with_header(sshc, '/system scheduler print detail')
        sus_dns, recommendation = self.check_results_ssh(res)

        return {'raw_data': res,
                'suspicious': sus_dns,
                'recommendation': recommendation}

    def check_results_ssh(self, res):
        sus_tasks = []
        recommendation = []

        for item in res:
            if (re.match(r'u\d+$', item['name'].lower())) or (('/tool fetch' in item['on-event']) or
                                                              ('url' in item['on-event']) or ('http' in item['on-event'])):
                sus_tasks.append(f'Task name: {item["name"]}, executes: {item["on-event"]} - severity: high')

        return sus_tasks, recommendation









