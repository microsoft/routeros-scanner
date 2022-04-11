# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import json
import traceback
import paramiko
import os
import datetime
import sys
import re

from commands.fwnat import FWNat
from commands.dns import DNS
from commands.files import Files
from commands.fwrules import FW
from commands.ports import Ports
from commands.proxy import Proxy
from commands.scheduler import Scheduler
from commands.socks import Socks
from commands.users import Users
from commands.version import Version
import query_nvd

CVES_PATH = './assets/mikrotik_cpe_match.json'


def main(args):
    all_data = {}
    commands = [Version(), Scheduler(), Files(), FWNat(), Proxy(), Socks(), DNS(), Users(), Ports(), FW()]

    if args.update or is_cves_file_updated():
        update_cves()

    print(f'** Mikrotik ip address: {args.ip}\n')

    with paramiko.SSHClient() as ssh_client:
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=args.ip, port=args.port, username=args.userName, password=args.password,
        look_for_keys=False, allow_agent=False)

        for command in commands:
            res = command.run_ssh(ssh_client)
            all_data[command.__name__] = res
    
        if args.J:
            print(json.dumps(all_data, indent=4))
        else:
            print_txt_results(all_data, args.concise)

def print_txt_results(res, concise):
    for command in res:
        if (not concise and res[command]["raw_data"]) or res[command]["recommendation"] or res[command]["suspicious"]:
            print(f'{command}:')
            for item in res[command]:
                if concise and item != "recommendation" and item != "suspicious":
                        continue
                if res[command][item]:
                    print(f'\t{item}:')
                    if type(res[command][item]) == list:
                        data = '\n\t\t'.join(json.dumps(i) for i in res[command][item])
                    else:
                        data = res[command][item]
                    print(f'\t\t{data}')

def is_cves_file_updated():
    if os.path.isfile(CVES_PATH):
        month_ago = datetime.datetime.now() - datetime.timedelta(30)
        modification_date = datetime.datetime.fromtimestamp(os.path.getmtime(CVES_PATH))
        need_update = month_ago > modification_date
        if need_update:
            print("** The CVE data file hasn't been update in the last month", file = sys.stderr)
    else:
        print("** There is no CVE data file", file = sys.stderr)
        need_update = True

    return need_update

def update_cves():
    print(f'** Trying to update the CVE json file', file = sys.stderr)
    try:
        ci = query_nvd.CVEsInterface()

        ver_cves = ci.nist_api('mikrotik', 'routeros')
        strip_no_routeros_version(ver_cves)

        if ver_cves:
            with open('./assets/mikrotik_cpe_match.json', 'w') as fjson:
                fjson.write(json.dumps(ver_cves, indent=4))
            print("** The CVE update process succeeded", file=sys.stderr)
        else:
            print(
                "** The CVE update process failed, if an older version of the json file is available, the program will use it, else the program won't return CVE data.",
                file=sys.stderr)
    except Exception:
        print(f"** The CVE update process failed, if an older version of the json file is available, the program will use it, else the program won't return CVE data.\n"
              f"   The exception message:\n {traceback.format_exc()}", file = sys.stderr)

def strip_no_routeros_version(cves):
    for cve in cves:
        for versions in cves[cve]:
            for ver in list(versions):
                if not is_routeros_version(versions[ver]):
                    versions.pop(ver)

def is_routeros_version(ver):
    return re.match(r'\d{1,2}\.\d{1,2}(\.\d{1,2})?', ver)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', help='The tested Mikrotik IP address', required=True)
    parser.add_argument('-p', '--port', help='The tested Mikrotik SSH port', default='22')
    parser.add_argument('-u', '--userName', help='User name with admin Permissions', required=True)
    parser.add_argument('-ps', '--password', help='The password of the given user name', default='')
    parser.add_argument('-J', help='Print the results as json format', action='store_true')
    parser.add_argument('-concise', help='Print out only suspicious items and recommendations', action='store_true')
    parser.add_argument('-update', help='Update the CVE Json file', action='store_true')
    args = parser.parse_args()

    main(args)
