#!/usr/bin/env python


# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import sys, os.path
parent_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(parent_dir)
from util.proxmox_session_handler import proxmox_session_handler



# -----------------------------------------------------------------------------
# Parse input file
# -----------------------------------------------------------------------------
def parse_input_file(input_file, proxmox_session_handler):
    
    # read in each line from the file
    with open(input_file, 'r') as f:
        content = f.readlines()
    
    # iterate through each account and create accounts
    for line in content:
        username, password = line.strip().split(',')
        proxmox_session_handler.create_account(username, password)
        vmid = proxmox_session_handler.clone_vm(username)
        proxmox_session_handler.grant_access(username, vmid)




# -----------------------------------------------------------------------------
# Run main
# -----------------------------------------------------------------------------
def run_main():
    p = proxmox_session_handler()

    parse_input_file(sys.argv[1], p)
    

    


# -----------------------------------------------------------------------------
# Run interactively
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Provide CSV file as input')
        exit()

    if not os.path.isfile(sys.argv[1]):
        print('Provide CSV file as input')
        exit()

    run_main()