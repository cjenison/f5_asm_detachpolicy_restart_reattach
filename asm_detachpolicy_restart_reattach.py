#!/usr/bin/python

# Home: https://github.com/cjenison/f5_asm_detachpolicy_restart_reattach.git
# Author: Chad Jenison (c.jenison@f5.com)

import argparse
import sys
import requests
import json
import copy
import getpass
from time import sleep

parser = argparse.ArgumentParser(description='A tool to detach ASM policies from virtual to allow some global change to ASM configuration, then restore policies to virtuals')
parser.add_argument('--user', '-u', help='username to use for authentication', required=True)
parser.add_argument('--bigip', '-b', help='IP or hostname of BIG-IP Management or Self IP')
parser.add_argument('--variable', help='ASM variable name to modify')
parser.add_argument('--value', help='Variable value')

args = parser.parse_args()

def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while 1:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")


def get_auth_token(bigip, username, password):
    authbip = requests.session()
    authbip.verify = False
    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % bigip
    token = authbip.post(authurl, headers=contentJsonHeader, auth=(username, password), data=json.dumps(payload)).json()['token']['token']
    print ('Got Auth Token: %s' % (token))
    return token


passwd = getpass.getpass('Enter Password for: %s: ' % (args.user))
bip = requests.session()
requests.packages.urllib3.disable_warnings()
bip.verify = False
contentJsonHeader = {'Content-Type': "application/json"}
authHeader = {'X-F5-Auth-Token': get_auth_token(args.bigip, args.user, passwd)}
bip.headers.update(authHeader)

asmPolicies = bip.get('https://%s/mgmt/tm/asm/policies?expandSubcollections=true' % (args.bigip)).json()
originalPolicies = {}
for policy in asmPolicies['items']:
    originalPolicies[policy['id']] = copy.deepcopy(policy)
    try:
        print ('Policy ID: %s - Name: %s - Virtuals: %s' % (policy['id'], policy['name'], json.dumps(policy['virtualServers'])))
    except:
        pass
    try:
        del policy['virtualServers']
    except:
        pass
    removeVirtualsFromPolicyPost = bip.patch('https://%s/mgmt/tm/asm/policies/%s' % (args.bigip, policy['id']), headers=contentJsonHeader, data=json.dumps(policy)).json()

settingId = ''
asmAdvancedSettings = bip.get('https://%s/mgmt/tm/asm/advanced-settings' % (args.bigip)).json()
for setting in asmAdvancedSettings['items']:
    if setting['name'] == args.variable:
        settingId = setting['id']
        patchPayload = {'name': args.variable, 'id': setting['id'], 'value': args.value}
        patchSetting = bip.patch('https://%s/mgmt/tm/asm/advanced-settings/%s' % (args.bigip, setting['id']), headers=contentJsonHeader, data=json.dumps(patchPayload)).json()
        print ('Response to Patch: %s' % (json.dumps(patchSetting)))

restartAsmPayload = {'command': 'run', 'utilCmdArgs': '-c \'tmsh restart sys service asm\''}
restartPost = bip.post('https://%s/mgmt/tm/util/bash' % (args.bigip), headers=contentJsonHeader, data=json.dumps(restartAsmPayload)).json()
#print('Response to Restart: %s' % (json.dumps(restartPost)))


if query_yes_no('Ready to Proceed with restoration of ASM Policy to Virtuals?', default="no"):
    pass

settingRead = bip.get('https://%s/mgmt/tm/asm/advanced-settings/%s' % (args.bigip, settingId)).json()
print ('SettingRead: %s' % (json.dumps(settingRead, indent=2)))

for policy in originalPolicies.keys():
    print ('Policy ID: %s\n' % (policy))
    if originalPolicies[policy].get('virtualServers'):
        restorePolicy = bip.patch('https://%s/mgmt/tm/asm/policies/%s' % (args.bigip, policy), headers=contentJsonHeader, data=json.dumps(originalPolicies[policy])).json()
        print ('Response: %s' % (json.dumps(restorePolicy)))
