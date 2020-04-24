#!/usr/bin/env python


# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import sys, os.path
parent_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(parent_dir)
from util.proxmox_session_handler import proxmox_session_handler



# -----------------------------------------------------------------------------
# Run main
# -----------------------------------------------------------------------------
def run_main():
    p = proxmox_session_handler()

    p.clone_vms()
    #p.get_vmid('host2', 'kali-template')

    

    
    

    


# -----------------------------------------------------------------------------
# Run interactively
# -----------------------------------------------------------------------------
if __name__ == "__main__":

    run_main()