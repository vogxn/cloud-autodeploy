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

xe vdi-destroy name-label=$vmname
xe vm-uninstall force=true vm=$vmname
