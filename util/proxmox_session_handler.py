#!/usr/bin/env python


# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import os.path
import requests
from requests.packages import urllib3
import configparser
import json



# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
config_file_location = os.path.abspath(os.path.join(os.path.dirname(__name__), 'config.cfg'))



# -----------------------------------------------------------------------------
# Handles ProxMox API sessions
# -----------------------------------------------------------------------------
class proxmox_session_handler():
    def __init__(self):
        config = configparser.ConfigParser()
        config.read(config_file_location)
        
        self.server = config['config']['server']
        self.port = config['config']['port']
        self.tls_verify = config.getboolean('config', 'tls_verify')
        self.username = config['authentication']['username']
        self.password = config['authentication']['password']
        self.login_realm = config['authentication']['realm']
        self.account_group = config['account']['group']
        self.account_realm = config['account']['realm']
        self.vmid = config['template']['vmid']
        self.node = config['template']['node']
        self.number = config.getint('template', 'number_to_clone')
        self.pool = config['template']['pool']
        self.name = config['template']['name']


        if not self.tls_verify:
            urllib3.disable_warnings()
        
        self.session = requests.Session()

        self.authenticate()



    # -----------------------------------------------------------------------------
    # Authenticate to ProxMox
    # -----------------------------------------------------------------------------
    def authenticate(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/ticket'
        payload = {
            'username': self.username + '@' + self.login_realm,
            'password': self.password
        }

        r = self.session.post(url, data=payload, verify=self.tls_verify)
        
        self.parse_response(r)

        self.token = r.json()['data']['CSRFPreventionToken']
        self.ticket = r.json()['data']['ticket']
        self.cookies = dict(PVEAuthCookie = self.ticket)        



    # -----------------------------------------------------------------------------
    # Create user account
    # -----------------------------------------------------------------------------
    def create_account(self, username, password):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/users'

        headers = {
            'CSRFPreventionToken': self.token
        }

        payload = {
            'userid': username + '@' + self.account_realm,
            'password': password,
            'groups': self.account_group,
        }

        r = self.session.post(url, headers=headers, data=payload, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        #print(json.dumps(r.json(), indent=2, sort_keys=True))



    # -----------------------------------------------------------------------------
    # Get users
    # -----------------------------------------------------------------------------
    def get_users(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/users'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        print(json.dumps(r.json(), indent=2, sort_keys=True))
    


    # -----------------------------------------------------------------------------
    # Get permissions
    # -----------------------------------------------------------------------------
    def get_permissions(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/permissions'

        payload = {
            'userid': self.username + '@' + self.login_realm
        }

        r = self.session.get(url, params=payload, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        print(json.dumps(r.json(), indent=2, sort_keys=True))



    # -----------------------------------------------------------------------------
    # Make sure the target node is online
    # -----------------------------------------------------------------------------
    def check_nodes(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        #print(json.dumps(r.json(), indent=2, sort_keys=True))
        
        j = r.json()

        for element in j['data']: # iterate through all returned nodes

            if element['node'] == self.node: # if our node is found

                if element['status'] == 'online': # its our node AND its online
                    return # we're good

                else: # its out node but its not online
                    print('Node ' + self.node + ' is offline! Exiting!')
                    exit()
        
        print('Node ' + self.node + ' not found! Exiting!')
        exit()
    


    # -----------------------------------------------------------------------------
    # Check that VMID is valid
    # -----------------------------------------------------------------------------
    def check_vmid(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + self.node + '/qemu'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        #print(json.dumps(r.json(), indent=2, sort_keys=True))

        j = r.json()

        for element in j['data']: # iterate through all returned VMs

            if element['vmid'] == self.vmid: # if our VM is found
                return # we're good
        
        print('VMID ' + self.vmid + ' not found! Exiting!')
        exit()
    


    # -----------------------------------------------------------------------------
    # Check that pool name is valid
    # -----------------------------------------------------------------------------
    def check_pool(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/cluster/resources'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        #print(json.dumps(r.json(), indent=2, sort_keys=True))
        #exit()

        j = r.json()

        for element in j['data']: # iterate through all returned VMs

            if element['type'] == 'pool' and element['pool'] == self.pool: # if element is our pool
                return # we're good
        
        print('Pool ' + self.pool + ' not found! Exiting!')
        exit()
    

    # -----------------------------------------------------------------------------
    # Get highest VMID
    # -----------------------------------------------------------------------------
    def get_starting_id(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + self.node + '/qemu'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        #print(json.dumps(r.json(), indent=2, sort_keys=True))

        j = r.json()
        highest_id = 0

        for element in j['data']: # iterate through all returned VMs

            if int(element['vmid']) > highest_id: # check if this node has a higher VMID than we've sen before
                highest_id = int(element['vmid'])
        
        return highest_id + 1 # return 1 higher than the highest VMID


    # -----------------------------------------------------------------------------
    # Clone VMs
    # -----------------------------------------------------------------------------
    def clone_vms(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + \
                self.node + '/qemu/' + self.vmid + '/clone'
        
        self.check_nodes() # make sure node is online
        self.check_vmid() # make sure VMID is valid
        self.check_pool() # make sure pool is valid

        newid = self.get_starting_id() # get VMID for new VM

        headers = {
            'CSRFPreventionToken': self.token
        }

        payload = {
            'newid': newid,
            'target': self.node,
            'pool': self.pool,
            'name': self.name
        }

        # set the number of clones to create
        number_to_clone = self.number

        # start looping
        while number_to_clone > 0:
            payload = {
                'newid': newid,
                'target': self.node,
                'pool': self.pool,
                'name': self.name
            }

            r = self.session.post(url, headers=headers, data=payload, cookies=self.cookies, verify=self.tls_verify)
            self.parse_response(r)
            
            number_to_clone -= 1 # decrement the number to clone by 1
            newid += 1 # increment the next VMID by 1

        





    # -----------------------------------------------------------------------------
    # Get VM info
    # -----------------------------------------------------------------------------
    def get_node_qemu_vm(self, node, vmid):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + node + '/qemu/' + vmid
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        #print(json.dumps(r.json(), indent=2, sort_keys=True))

        j = r.json()
        nodes = []
        for node in j['data']:
            if node['name'] == self.template:
                nodes.append(node['vmid'])
        
        return nodes



    # -----------------------------------------------------------------------------
    # Parse response
    # -----------------------------------------------------------------------------
    def parse_response(self, response):
        if str(response.status_code).startswith('3'):
            print('Response code: ' + str(response.status_code))
            print('Verify server address: ' + response.url)
            exit()
        
        elif response.status_code == 401:
            print('Response code: ' + str(response.status_code))
            print('Verify account credentials')
            print(response.text)
            exit()
        
        elif str(response.status_code).startswith('4'):
            print('Response code: ' + str(response.status_code))
            print('Verify server address: ' + response.url)
            print(response.text)
            exit()
        
        elif str(response.status_code).startswith('5'):
            print('Response code: ' + str(response.status_code))
            print('Server error')
            print(response.text)
            exit()
        
        elif str(response.status_code).startswith('2'):
            #print(response.status_code)
            #print(json.dumps(response.json(), indent=2, sort_keys=True))
            return
        
        else:
            print('Response code: ' + str(response.status_code))
            print('Unknown error')
            exit()