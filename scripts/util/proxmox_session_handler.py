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

        self.nodes_list = config['template']['node'].split(',')
        self.nodes_counter = 0
        
        self.server = config['config']['server']
        self.port = config['config']['port']
        self.tls_verify = config.getboolean('config', 'tls_verify')
        self.username = config['authentication']['username']
        self.password = config['authentication']['password']
        self.login_realm = config['authentication']['realm']
        self.account_group = config['account']['group']
        self.account_realm = config['account']['realm']
        self.role = config['account']['role']
        self.name = config['template']['name']
        self.number = config.getint('template', 'number_to_clone')
        self.pool = config['template']['pool']
        self.prefix = config['template']['prefix']


        if not self.tls_verify:
            urllib3.disable_warnings()
        
        self.session = requests.Session()

        self.authenticate()



    # -----------------------------------------------------------------------------
    # Returns the node to use
    # -----------------------------------------------------------------------------
    def get_node(self):
        node = self.nodes_list[self.nodes_counter] # get node
        self.nodes_counter += 1 # increment node counter

        if self.nodes_counter > len(self.nodes_list) -1: # if nodes counter is too big
            self.nodes_counter = 0 # reset to 0
        
        return node



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
        if self.get_user_exists(username):
            return

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

        #print(json.dumps(r.json(), indent=2, sort_keys=True))
        #exit()

        j = r.json()
        users = []
        for user in j['data']:
            users.append(user['userid'])
        
        return users
    


    # -----------------------------------------------------------------------------
    # Get user exists
    # -----------------------------------------------------------------------------
    def get_user_exists(self, username):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/users'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        #print(json.dumps(r.json(), indent=2, sort_keys=True))

        j = r.json()

        for element in j['data']:
            if element['userid'] == username + '@' + self.account_realm:
                return True
        
        return False
    


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
        
        for node in self.nodes_list: # iterate through all our nodes
            found = False

            for element in j['data']: # iterate through all returned nodes

                if element['node'] == node: # if our node is found
                    found = True

                    if element['status'] == 'offline': # its our node AND its online
                        print('Node ' + node + ' is offline! Exiting!')
                        exit()                        
        
            if not found:
                print('Node ' + node + ' not found! Exiting!')
                exit()
        
        return
    


    # -----------------------------------------------------------------------------
    # Check that VMID is valid
    # -----------------------------------------------------------------------------
    def get_vmid(self, node, name):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + node + '/qemu'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        #print(json.dumps(r.json(), indent=2, sort_keys=True))
        #exit()

        j = r.json()

        for element in j['data']: # iterate through all returned VMs

            if element['name'] == name: # if our VM is found
                return element['vmid']
        
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
    # Get new VMID to use when cloning a VM
    # -----------------------------------------------------------------------------
    def get_newid(self, node):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + node + '/qemu'
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
    # Clone multiple VMs
    # -----------------------------------------------------------------------------
    def clone_vms(self, name=""):
        self.check_nodes() # make sure nodes are online
        self.check_pool() # make sure pool is valid

        headers = {
            'CSRFPreventionToken': self.token
        }

        # set the number of clones to create
        number_to_clone = self.number

        # start looping
        while number_to_clone > 0:
            node = self.get_node() # get node to use
            vmid = self.get_vmid(node, self.name) # make sure VMID is valid

            payload = {
                'newid': self.get_newid(node),
                'target': self.get_node(),
                'pool': self.pool
            }

            url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + \
                node + '/qemu/' + vmid + '/clone'

            r = self.session.post(url, headers=headers, data=payload, cookies=self.cookies, verify=self.tls_verify)
            self.parse_response(r)
            
            number_to_clone -= 1 # decrement the number to clone by 1
    


    # -----------------------------------------------------------------------------
    # Clone single VM
    # -----------------------------------------------------------------------------
    def clone_vm(self, name=""):
        self.check_nodes() # make sure nodes are online
        self.check_pool() # make sure pool is valid

        headers = {
            'CSRFPreventionToken': self.token
        }

        node = self.get_node() # get node to use
        vmid = self.get_vmid(node, self.name) # make sure VMID is valid

        if name != "":
            name = self.prefix + name
        
        newid = self.get_newid(node)

        payload = {
            'newid': newid,
            'target': self.get_node(),
            'pool': self.pool,
            'name': name
        }

        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + \
            node + '/qemu/' + vmid + '/clone'

        r = self.session.post(url, headers=headers, data=payload, cookies=self.cookies, verify=self.tls_verify)
        self.parse_response(r)

        return newid

        

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
    # Grant user access to a VM
    # -----------------------------------------------------------------------------
    def grant_access(self, username, vmid):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/acl'

        headers = {
            'CSRFPreventionToken': self.token
        }

        payload = {
            'users': username + '@' + self.account_realm,
            'roles': self.role,
            'path': '/vms/' + str(vmid),
        }
        
        r = self.session.put(url, headers=headers, data=payload, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        #print(json.dumps(r.json(), indent=2, sort_keys=True))
    


    # -----------------------------------------------------------------------------
    # Delete user
    # -----------------------------------------------------------------------------
    def delete_user(self, userid):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/users/' + userid

        headers = {
            'CSRFPreventionToken': self.token
        }
        
        r = self.session.delete(url, headers=headers, cookies=self.cookies, verify=self.tls_verify)

        self.parse_response(r)

        #print(json.dumps(r.json(), indent=2, sort_keys=True))
        #exit()



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