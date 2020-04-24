#!/usr/bin/env python


# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import sys, os.path
parent_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(parent_dir)
from util.proxmox_session_handler import proxmox_session_handler



# -----------------------------------------------------------------------------
# Parse users
# -----------------------------------------------------------------------------
def parse_users(users):
    prefix = str(sys.argv[1])

    parsed_users = []

    for user in users:
        if user.startswith(prefix):
            parsed_users.append(user)

    return parsed_users



# -----------------------------------------------------------------------------
# Delete users
# -----------------------------------------------------------------------------
def delete_users(proxmox_session_handler, users):
    for user in users:
        proxmox_session_handler.delete_user(user)




# -----------------------------------------------------------------------------
# Run main
# -----------------------------------------------------------------------------
def run_main():
    p = proxmox_session_handler()

    users = p.get_users()
    parsed_users = parse_users(users)
    
    print('Identified ' + str(len(parsed_users)) + ' to be deleted.')
    proceed = input('Proceed? (y/n) ')

    if proceed.lower().startswith('y'):
        delete_users(p, parsed_users)

    else:
        exit()
    

    


# -----------------------------------------------------------------------------
# Run interactively
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Provide prefix pattern of user accounts to delete')
        exit()

    run_main()