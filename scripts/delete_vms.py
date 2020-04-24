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
def parse_vms(vms):
    prefix = str(sys.argv[1])

    parsed_vms = []

    for node in vms: # iterate through each node

        for vmid, name in vms[node]: # iterate through each vm (on each node)
            
            if name.startswith(prefix):
                parsed_vms.append((node, vmid))
    
    return parsed_vms



# -----------------------------------------------------------------------------
# Delete users
# -----------------------------------------------------------------------------
def delete_vms(proxmox_session_handler, vms):
    for node, vmid in vms:
        proxmox_session_handler.delete_vm(node, vmid)




# -----------------------------------------------------------------------------
# Run main
# -----------------------------------------------------------------------------
def run_main():
    p = proxmox_session_handler()

    vms = p.get_vms()
    
    parsed_vms = parse_vms(vms)
    
    print('Identified ' + str(len(parsed_vms)) + ' to be deleted.')
    proceed = input('Proceed? (y/n) ')

    if proceed.lower().startswith('y'):
        delete_vms(p, parsed_vms)

    else:
        exit()
    

    


# -----------------------------------------------------------------------------
# Run interactively
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Provide prefix pattern of VMs to delete')
        exit()

    run_main()