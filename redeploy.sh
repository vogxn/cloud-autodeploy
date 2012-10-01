#!/bin/bash
usage() {
  printf "Usage: %s:\n
	[-s path to secondary ]  \n
	[-h hypervisor type (kvm|xenserver|vmware) ]  \n
	[-t session-timeout ] \n
	[-a tarball path ] \n
	[-d db node url ]\n" $(basename $0) >&2

  printf "\nThe -s flag will clean the secondary path and install the specified
hypervisor routing template as per -h, if -h is not given then xenserver is
assumed\n"	

}

failed() {
	exit $1
}

#flags
dflag=
sflag=
tflag=
hflag=
aflag=

VERSION="1.0.1"
echo "Redeploy Version: $VERSION"


#some defaults
spath='/export/home/bvt/secondary'
apath='.'
hypervisor='xenserver'
timeout=300
sstor='nfs2.lab.vmops.com'
tmpltstor='nfs1.lab.vmops.com'

while getopts 'a:t:d:s:h:' OPTION
do
  case $OPTION in
  a)    aflag=1
		apath="$OPTARG"
  		;;
  s)    sflag=1
		spath="$OPTARG"
  		;;
  d)    dflag=1
		dbase="$OPTARG"
		;;
  h)    hflag=1
		hypervisor="$OPTARG"
		;;
  t)    tflag=1
		timeout="$OPTARG"
		;;
  ?)	usage
		failed 2
		;;
  esac
done

if [[ -e /etc/redhat-release ]]
then 
	cat /etc/redhat-release
else
	echo "script works on rpm environments only"
	exit 5
fi

#check if process is running
proc=$(ps aux | grep cloud | wc -l)
if [[ $proc -lt 2 ]]
then
        echo "Cloud process not running"
        if [[ -e /var/run/cloud-management.pid ]]
        then
            rm -f /var/run/cloud-management.pid
        fi
else
        #stop service
        service cloud-management stop
fi

if [[ "$aflag" == "1" ]]
then
	#clear up yum cache
	rm -rf /var/cache/yum/* /var/cache/cloud
	#erase old archives
	if [[ "$(rpm -qa | grep cloud | wc -l)" -gt 0 ]]
	then
		packages=$(rpm -qa | grep cloud | tr "\n" " ")
		yum -y erase $packages
	fi
	#install with new archive
	if [[ -f $apath ]]
	then
		dir=$RANDOM
		mkdir -p /tmp/$dir
		tar -xvzf $apath -C /tmp/$dir
		installer_script=$(find /tmp/$dir -name install.sh)
		bash $installer_script -m 
                bash rm -rf /tmp/$dir
	else
		echo "Cannot find cloudstack in $apath"
		exit 5
	fi
fi

sed -iv 's/download.cloud.com/nfs1.lab.vmops.com/g' /usr/share/cloud/setup/templates.sql

#reset session-timeout
sed -i "s/<session-timeout>30</<session-timeout>$timeout</g" /etc/cloud/management/web.xml

#TODO: archive old logs
#refresh log state 
cat /dev/null > /var/log/cloud/management/management-server.log
cat /dev/null > /var/log/cloud/management/api-server.log
cat /dev/null > /var/log/cloud/management/catalina.out

if [ "$dflag" == "1" ]
then
	if [ "$dbase" != "" ]
	then
		#drop databases
		mysql -uroot -Dcloud -h$dbase -e"drop database cloud; drop database cloud_usage;"

		#redeploy databases
		cloud-setup-databases cloud:cloud@$dbase --deploy-as=root 
	fi
else
	echo "Only seeding template. No database refresh"
fi

#replace disk size reqd to 1GB max
sed -i 's/DISKSPACE=5120000/DISKSPACE=20000/g' /usr/lib64/cloud/common/scripts/storage/secondary/cloud-install-sys-tmplt

if [[ "$sflag" == "1" ]]
then
	mkdir -p /tmp/secondary
	mount -t nfs $sstor:$spath /tmp/secondary
	rm -rf /tmp/secondary/*

	if [[ "$hflag" == "1" && "$hypervisor" == "xenserver" ]]
	then
		bash -x /usr/lib64/cloud/common/scripts/storage/secondary/cloud-install-sys-tmplt -m /tmp/secondary/ -u http://$tmpltstor/templates/routing/debian/Jan06_2012/systemvm.vhd.bz2 -h xenserver
	elif [[ "$hflag" == "1" && "$hypervisor" == "kvm" ]]
	then
		bash -x /usr/lib64/cloud/common/scripts/storage/secondary/cloud-install-sys-tmplt -m /tmp/secondary/ -u http://$tmpltstor/templates/routing/debian/Jan06_2012/systemvm.qcow2.bz2 -h kvm
	elif [[ "$hflag" == "1" && "$hypervisor" == "vmware" ]]
	then
		bash -x /usr/lib64/cloud/common/scripts/storage/secondary/cloud-install-sys-tmplt -m /tmp/secondary/ -u http://$tmpltstor/templates/routing/debian/Jan06_2012/systemvm.ova -h vmware
	else
		bash -x /usr/lib64/cloud/common/scripts/storage/secondary/cloud-install-sys-tmplt -m /tmp/secondary/ -u http://$tmpltstor/templates/routing/debian/Jan06_2012/systemvm.vhd.bz2 -h xenserver
	fi
	umount /tmp/secondary
fi

#setup management
cloud-setup-management 
