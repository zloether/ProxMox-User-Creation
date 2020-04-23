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