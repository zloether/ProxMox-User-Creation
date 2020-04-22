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

        if not self.tls_verify:
            urllib3.disable_warnings()
        
        self.session = requests.Session()
        
    

    # -----------------------------------------------------------------------------
    # Authenticate to ProxMox
    # -----------------------------------------------------------------------------
    def authenticate(self):
        url = 'https://' + self.server + ':' + self.port + '/api2/json/access/ticket'
        payload = {
            'username': self.username + '@pve',
            'password': self.password
        }

        r = self.session.post(url, data=payload, verify=self.tls_verify)
        print(json.dumps(r.json(), indent=2, sort_keys=True))

        self.ticket = r.json()['data']['ticket']
        print(self.ticket)