#!/bin/bash

# Uninstalls a given VM

usage() {
  printf "Usage: %s: -n <vm name>\n" $(basename $0) >&2
  exit 2
}

vmname=
while getopts 'n:' OPTION
do
    case $OPTION in
        n)    vmname="$OPTARG"
            ;;
        ?)    usage
            exit 1
            ;;
    esac
done

vdi_uuid=$(xe vdi-list name-label=test | grep ^uuid | awk '{print $5}')
xe vdi-destroy uuid=$vdi_uuid
xe vm-uninstall force=true vm=$vmname
