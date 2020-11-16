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
        
        if not str(r.status_code).startswith('2'):
            print('Error! Failed to authenticate.')
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()
            

        self.token = r.json()['data']['CSRFPreventionToken']
        self.ticket = r.json()['data']['ticket']
        self.cookies = dict(PVEAuthCookie = self.ticket)
        self.headers = {'CSRFPreventionToken': self.token}




    # -----------------------------------------------------------------------------
    # Create user account
    # -----------------------------------------------------------------------------
    def create_account(self, username, password):
        if self.get_user_exists(username):
            return

        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/users'

        payload = {
            'userid': username + '@' + self.account_realm,
            'password': password,
            'groups': self.account_group,
        }

        r = self.session.post(url, headers=self.headers, data=payload, cookies=self.cookies, verify=self.tls_verify)

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to create account ' + str(username))
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

        #print(json.dumps(r.json(), indent=2, sort_keys=True))



    # -----------------------------------------------------------------------------
    # Get users
    # -----------------------------------------------------------------------------
    def get_users(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/users'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to get users.')
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

        #print(json.dumps(r.json(), indent=2, sort_keys=True))
        #exit()

        j = r.json()
        users = []
        for user in j['data']:
            users.append(user['userid'])
        
        return users

    

    # -----------------------------------------------------------------------------
    # Get users with details
    # -----------------------------------------------------------------------------
    def get_users_details(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/users'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to get users.')
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

        #print(json.dumps(r.json(), indent=2, sort_keys=True))
        #exit()

        j = r.json()
        
        return j
    


    # -----------------------------------------------------------------------------
    # Get user exists
    # -----------------------------------------------------------------------------
    def get_user_exists(self, username):
        users = self.get_users()

        for element in users:
            if element == username + '@' + self.account_realm:
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

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to get permissions.')
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

        print(json.dumps(r.json(), indent=2, sort_keys=True))



    # -----------------------------------------------------------------------------
    # Make sure the target node is online
    # -----------------------------------------------------------------------------
    def check_nodes(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to check nodes.')
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

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
    # Returns all online nodes
    # -----------------------------------------------------------------------------
    def get_nodes(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to get nodes.')
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()
        
        j = r.json()

        nodes = []
        for element in j['data']: # iterate through all returned nodes
            if element['status'] == 'online': # if its online
                nodes.append(element['node'])
        
        return nodes

    

    # -----------------------------------------------------------------------------
    # get all VMIDs
    # -----------------------------------------------------------------------------
    def get_vmids(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/cluster/resources'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)
        
        if not str(r.status_code).startswith('2'):
            print('Error! Failed to get vms2.')
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()
        

        j = r.json()

        vms = {}
        for element in j['data']: # iterate through all resources
            if element['type'] == 'qemu': # if its a VM
                vmid = str(element['vmid'])
                node = element['node']
                
                

                if not node in vms:
                    vms[node] = [vmid]

                else:
                    vms[node].append(vmid)
        
        return vms




    # -----------------------------------------------------------------------------
    # get all VMs from online nodes
    # -----------------------------------------------------------------------------
    def get_vms(self):
        nodes = self.get_nodes()
        
        vms = {}
        for node in nodes: # iterate through all the nodes

            url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + node + '/qemu'
            r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

            if not str(r.status_code).startswith('2'):
                print('Error! Failed to get vms.')
                print('Status code: ' + str(r.status_code))
                #print(json.dumps(r.json(), indent=2, sort_keys=True))
                print(r.text)
                print(vms)
                exit()

            #print(json.dumps(r.json(), indent=2, sort_keys=True))
            #exit()

            j = r.json()

            vms_on_this_node = []
            for element in j['data']: # iterate through all returned VMs for this node
                vms_on_this_node.append((element['vmid'], element['name']))
                
            vms[node] = vms_on_this_node

        return vms
    


    # -----------------------------------------------------------------------------
    # delete VM
    # -----------------------------------------------------------------------------
    def delete_vm(self, node, vmid):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + node + '/qemu/' + vmid
        
        r = self.session.delete(url, headers=self.headers, cookies=self.cookies, verify=self.tls_verify)

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to delete VMID: ' + str(vmid) + ' on node: ' + str(node))
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

        #print(json.dumps(r.json(), indent=2, sort_keys=True))
        #exit()



    # -----------------------------------------------------------------------------
    # Check that VMID is valid
    # -----------------------------------------------------------------------------
    def get_vmid(self, node, name):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + node + '/qemu'
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to get vmid on node ' + str(node))
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

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

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to check pool.')
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

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
    def get_newid(self):
        vms = self.get_vmids()

        highest_id = 100

        for host in vms:
            for vmid in vms[host]:
                if int(vmid) > highest_id:
                    highest_id = int(vmid)
                
        
        return highest_id + 1 # return 1 higher than the highest VMID


    # -----------------------------------------------------------------------------
    # Clone multiple VMs
    # -----------------------------------------------------------------------------
    def clone_vms(self, name=""):
        self.check_nodes() # make sure nodes are online
        self.check_pool() # make sure pool is valid

        # set the number of clones to create
        number_to_clone = self.number

        # start looping
        while number_to_clone > 0:
            node = self.get_node() # get node to use
            vmid = self.get_vmid(node, self.name) # make sure VMID is valid

            self.clone_vm(name)
            
            number_to_clone -= 1 # decrement the number to clone by 1
    


    # -----------------------------------------------------------------------------
    # Clone single VM
    # -----------------------------------------------------------------------------
    def clone_vm(self, name=""):
        self.check_nodes() # make sure nodes are online
        self.check_pool() # make sure pool is valid

        node = self.get_node() # get node to use
        vmid = self.get_vmid(node, self.name) # make sure VMID is valid

        if name != "":
            name = self.prefix + name
        
        newid = self.get_newid()

        payload = {
            'newid': newid,
            'target': node,
            'pool': self.pool,
            'name': name.strip()
        }

        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + \
            node + '/qemu/' + vmid + '/clone'


        r = self.session.post(url, headers=self.headers, data=payload, cookies=self.cookies, verify=self.tls_verify)
        
        if not str(r.status_code).startswith('2'):
            print('Error! Failed to clone vm on node ' + str(node))
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

        return newid

        

    # -----------------------------------------------------------------------------
    # Get VM info
    # -----------------------------------------------------------------------------
    def get_vm(self, node, vmid):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/nodes/' + node + '/qemu/' + vmid
        r = self.session.get(url, cookies=self.cookies, verify=self.tls_verify)

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to get VMID ' + str(vmid) + ' on node ' + str(node))
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

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

        userid = username + '@' + self.account_realm

        payload = {
            'users': userid,
            'roles': self.role,
            'path': '/vms/' + str(vmid),
        }
        
        r = self.session.put(url, headers=self.headers, data=payload, cookies=self.cookies, verify=self.tls_verify)

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to grant access to user ' + str(userid) + ' on vmid ' + str(vmid))
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

        #print(json.dumps(r.json(), indent=2, sort_keys=True))
    


    # -----------------------------------------------------------------------------
    # Delete user
    # -----------------------------------------------------------------------------
    def delete_user(self, userid):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/users/' + userid
    
        r = self.session.delete(url, headers=self.headers, cookies=self.cookies, verify=self.tls_verify)

        if not str(r.status_code).startswith('2'):
            print('Error! Failed to delete user ' + str(userid))
            print('Status code: ' + str(r.status_code))
            print(json.dumps(r.json(), indent=2, sort_keys=True))
            exit()

        #print(json.dumps(r.json(), indent=2, sort_keys=True))
        #exit()
