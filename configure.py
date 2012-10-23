from ConfigParser import ConfigParser
from bashUtils import bash
from marvin import configGenerator
from marvin import remoteSSHClient
from marvin import dbConnection
from argparse import ArgumentParser
from syslookup import ipmitable
from syslookup import mactable
from time import sleep as delay
from netaddr import IPNetwork
from netaddr import IPAddress
import contextlib
from contextlib import closing
import telnetlib
import bashUtils
import logging
import threading
import Queue
import marvin
import sys
import os
import random
import string
import urllib2
import urlparse
import socket
import select
import errno

WORKSPACE="."
IPMI_PASS="calvin"
CBLR_HOME={ 
    "eth0" :
    {
        "network" : "10.223.75.0/25",
        "gateway" : "10.223.75.10"
    },
    "eth1":
    {
        "network" : "10.223.78.0/25",
        "gateway" : "10.223.78.2"
    },
    "eth2":
    {
        "network" : "10.223.78.128/25",
        "gateway" : "10.223.78.130"
    },
}

def initLogging(logFile=None, lvl=logging.INFO):
    try:
        if logFile is None:
            logging.basicConfig(level=lvl, \
                                format="'%(asctime)-6s: %(name)s \
                                (%(threadName)s) - %(levelname)s - %(message)s'") 
        else: 
            logging.basicConfig(filename=logFile, level=lvl, \
                                format="'%(asctime)-6s: %(name)s \
                                (%(threadName)s) - %(levelname)s - %(message)s'") 
    except:
        logging.basicConfig(level=lvl) 

def mkdirs(path):
    dir = bash("mkdir -p %s" % path)

def fetch(filename, url, path):
    try:
        zipstream = urllib2.urlopen(url)
        tarball = open('/tmp/%s' % filename, 'wb')
        tarball.write(zipstream.read())
        tarball.close()
    except urllib2.URLError, u:
        raise u
    except IOError:
        raise
    bash("mv /tmp/%s %s" % (filename, path))

def cobblerHomeResolve(ip_address):
    cblr_home_1 = IPNetwork(CBLR_HOME["eth0"]["network"])
    cblr_home_2 = IPNetwork(CBLR_HOME["eth1"]["network"])
    cblr_home_3 = IPNetwork(CBLR_HOME["eth2"]["network"])

    ipAddr = IPAddress(ip_address)
    
    if ipAddr in cblr_home_1:
        return CBLR_HOME["eth0"]["gateway"]
    elif ipAddr in cblr_home_2:
        return CBLR_HOME["eth1"]["gateway"]
    elif ipAddr in cblr_home_3:
        return CBLR_HOME["eth2"]["gateway"]
    else:
        return CBLR_HOME["eth0"]["gateway"]

def configureManagementServer(mgmt_host):
    """
    We currently configure all mgmt servers on a single xen HV. In the future
    replace this by launching instances via the API on a IaaS cloud using
    desired template
    """
    mgmt_vm = mactable[mgmt_host]
    mgmt_ip = mactable[mgmt_host]["address"]

    #Remove and re-add cobbler system
    bash("cobbler system remove --name=%s"%mgmt_host)
    bash("cobbler system add --name=%s --hostname=%s --mac-address=%s \
         --netboot-enabled=yes --enable-gpxe=no \
         --profile=%s --server=%s"%(mgmt_host, mgmt_host, mgmt_vm["ethernet"],
                                    mgmt_host, cobblerHomeResolve(mgmt_ip)));
    bash("cobbler sync")

    #Revoke all certs from puppetmaster
    bash("puppet cert clean %s.cloudstack.org"%mgmt_host)

    #Start VM on xenserver
    xenssh = \
    remoteSSHClient.remoteSSHClient(mactable["infraxen"]["address"],
                                    22, "root",
                                    mactable["infraxen"]["password"])

    logging.debug("bash vm-start.sh -n %s -m %s"%(mgmt_host, mgmt_vm["ethernet"]))
    xenssh.execute("xe vm-uninstall force=true vm=%s"%mgmt_host)
    out = xenssh.execute("bash vm-start.sh -n %s -m %s"%(mgmt_host,
                                                  mgmt_vm["ethernet"]))

    logging.info("started mgmt server with uuid: %s. Waiting for services .."%out[1]);
    return mgmt_host

def _openIntegrationPort(csconfig):
    dbhost = csconfig.dbSvr.dbSvr
    dbuser = csconfig.dbSvr.user
    dbpasswd = csconfig.dbSvr.passwd
    logging.debug("opening the integration port on %s for %s with passwd %s"%(dbhost, dbuser, dbpasswd))
    conn = dbConnection.dbConnection(dbhost, 3306, dbuser, dbpasswd, "cloud")
    uquery = "update configuration set value=%s where name=%s" 
    conn.execute(uquery, (csconfig.mgtSvr[0].port, 'integration.api.port'))
    squery = "select name, value from configuration where name=%s"
    logging.info("integration port open: "%conn.execute(squery, ('integration.api.port',)))
       
def mountAndClean(host, path):
    """
    Will mount and clear the files on NFS host in the path given. Obviously the
    NFS server should be mountable where this script runs
    """
    mnt_path = "/tmp/" + ''.join([random.choice(string.ascii_uppercase) for x in xrange(0, 10)])
    mkdirs(mnt_path)
    logging.info("cleaning up %s:%s" % (host, path))
    mnt = bash("mount -t nfs %s:%s %s" % (host, path, mnt_path))
    erase = bash("rm -rf %s/*" % mnt_path)
    umnt = bash("umount %s" % mnt_path)
   
def cleanPrimaryStorage(cscfg):
    """
    Clean all the NFS primary stores and prepare them for the next run
    """
    for zone in cscfg.zones:
        for pod in zone.pods:
            for cluster in pod.clusters:
                for primaryStorage in cluster.primaryStorages:
                    if urlparse.urlsplit(primaryStorage.url).scheme == "nfs":
                        mountAndClean(urlparse.urlsplit(primaryStorage.url).hostname, urlparse.urlsplit(primaryStorage.url).path)
    logging.info("Cleaned up primary stores")

def seedSecondaryStorage(cscfg, hypervisor):
    """
    erase secondary store and seed system VM template via puppet. The
    secseeder.sh script is executed on mgmt server bootup which will mount and
    place the system VM templates on the NFS
    """
    mgmt_server = cscfg.mgtSvr[0].mgtSvrIp
    logging.info("Secondary storage seeded via puppet with systemvm templates")
    bash("rm -f /etc/puppet/modules/cloudstack/files/secseeder.sh")
    for zone in cscfg.zones:
        for sstor in zone.secondaryStorages:
            shost = urlparse.urlsplit(sstor.url).hostname
            spath = urlparse.urlsplit(sstor.url).path
            logging.info("seeding %s systemvm template on %s @ %s"%(hypervisor, shost, spath))
            bash("echo '/bin/bash /root/redeploy.sh -s %s -h %s' >> /etc/puppet/modules/cloudstack/files/secseeder.sh"%(spath, hypervisor))
    bash("chmod +x /etc/puppet/modules/cloudstack/files/secseeder.sh")

def refreshHosts(cscfg, hypervisor="xen", profile="xen602"):
    """
    Removes cobbler system from previous run. 
    Creates a new system for current run.
    Ipmi boots from PXE - default to Xenserver profile
    """
    hostlist = []
    for zone in cscfg.zones:
        for pod in zone.pods:
            for cluster in pod.clusters:
                for host in cluster.hosts:
                    hostname = urlparse.urlsplit(host.url).hostname
                    hostlist.append(hostname)
                    logging.debug("attempting to refresh host %s"%hostname)

                    #revoke certs
                    bash("puppet cert clean %s.cloudstack.org"%hostname)

                    #setup cobbler profiles and systems
                    try:
                        hostmac = mactable[hostname]['ethernet']
                        hostip = mactable[hostname]['address']
                        bash("cobbler system remove \
                             --name=%s"%(hostname))
                        bash("cobbler system add --name=%s --hostname=%s \
                             --mac-address=%s --netboot-enabled=yes \
                             --enable-gpxe=no --profile=%s --server=%s"%(hostname, hostname,
                                                             hostmac, profile,
                                                                         cobblerHomeResolve(hostip)))

                        bash("cobbler sync")
                    except KeyError:
                        logging.error("No mac found against host %s. Exiting"%hostname)
                        sys.exit(2)

                    #set ipmi to boot from PXE
                    try:
                        ipmi_hostname = ipmitable[hostname]
                        logging.debug("found IPMI nic on %s for host %s"%(ipmi_hostname, hostname))
                        bash("ipmitool -Uroot -P%s -H%s chassis bootdev \
                             pxe"%(IPMI_PASS, ipmi_hostname))
                        bash("ipmitool -Uroot -P%s -H%s chassis power cycle"
                             %(IPMI_PASS, ipmi_hostname))
                        logging.debug("Sent PXE boot for %s"%ipmi_hostname)
                    except KeyError:
                        logging.error("No ipmi host found against %s. Exiting"%hostname)
                        sys.exit(2)

    delay(5) #to begin pxe boot process or wait returns immediately
    return hostlist

def _isPortListening(host, port, timeout=120):
    """
    Scans 'host' for a listening service on 'port'
    """
    tn = None
    while timeout > 0:
        try:
            tn = telnetlib.Telnet(host, port, timeout=timeout)
            break
        except Exception:
            delay(1)
            timeout = timeout - 1
    if tn is None:
        logging.error("No service listening on port %s:%d"%(host, port))
        return False 
    else:
        logging.info("Unrecognizable service up on %s:%d"%(host, port))
        return True

def _isPortOpen(hostQueue, port=22):
    """
    Checks if there is an open socket on specified port. Default is SSH
    """
    ready = []
    host = hostQueue.get()
    while True:
        channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        channel.settimeout(20)
        try:
            logging.debug("Attempting port=%s connect to host %s"%(port, host))
            err = channel.connect_ex((host, port))
        except socket.error, e:
            logging.debug("encountered %s retrying in 5s"%e)
            delay(5)
        finally:
            if err == 0:
                ready.append(host)
                logging.info("host: %s is ready"%host)
                break
            else:
                logging.debug("[%s] host %s is not ready. Retrying"%(err, host))
                delay(5)
                channel.close()
    hostQueue.task_done()

def waitForHostReady(hostlist):
    logging.info("Waiting for hosts %s to refresh"%hostlist)
    hostQueue = Queue.Queue()

    for host in hostlist:
        t = threading.Thread(name='HostWait-%s'%hostlist.index(host), target=_isPortOpen,
                             args=(hostQueue, ))
        t.setDaemon(True)
        t.start()

    [hostQueue.put(host) for host in hostlist]
    hostQueue.join()
    logging.info("All hosts %s are up"%hostlist)
    
def init():
    initLogging()
        
if __name__ == '__main__':
    init()

    parser = ArgumentParser()
    parser.add_argument("-v", "--hypervisor", action="store", default="xen",
                      dest="hypervisor", help="hypervisor type")
    parser.add_argument("-d", "--distro", action="store", default="rhel",
                      dest="distro", help="management server distro")
    parser.add_argument("-s", "--skip-host", action="store_true", default=False,
                      dest="skip_host", help="Skip Host Refresh")
    parser.add_argument("-p", "--profile", action="store", default="xen602",
                      dest="profile", help="cobbler profile for hypervisor")
    options = parser.parse_args()

    if options.hypervisor == "xen":
        auto_config = "xen.cfg"
    elif options.hypervisor == "kvm":
        auto_config = "kvm.cfg"
    else:
        auto_config = "xen.cfg"

    mgmt_host = "cloudstack-"+options.distro
    logging.info("configuring %s for hypervisor %s"%(mgmt_host,
                                                     options.hypervisor))

    cscfg = configGenerator.get_setup_config(auto_config)

    logging.info("Configuring management server")
    mgmtHost = configureManagementServer(mgmt_host)
    hosts = []
    if not options.skip_host:
        logging.info("Reimaging hosts with %s profile for the %s \
                     hypervisor"%(options.profile, options.hypervisor))
        hosts = refreshHosts(cscfg, options.hypervisor, options.profile)
    else:
        logging.info("Skipping clean up of the HV hosts")

    seedSecondaryStorage(cscfg, options.hypervisor)
    cleanPrimaryStorage(cscfg)

    hosts.append(mgmtHost)
    waitForHostReady(hosts)
    delay(5)
    # Re-check because ssh connect works soon as post-installation occurs. But 
    # server is rebooted after post-installation. Assuming the server is up is
    # wrong in these cases. To avoid this we will check again before continuing
    # to add the hosts to cloudstack
    waitForHostReady(hosts)
    delay(5)

    if _isPortListening(host=mgmt_host, port=22, timeout=10) and _isPortListening(host=mgmt_host, port=3306, timeout=10):
        _openIntegrationPort(cscfg)
        mgmt_ip = mactable[mgmt_host]["address"]
        mgmt_pass = mactable[mgmt_host]["password"]
        with contextlib.closing(remoteSSHClient.remoteSSHClient(mgmt_ip, 22, "root", mgmt_pass)) as ssh:
            ssh.execute("mysql -ucloud -Dcloud -pcloud -e'update configuration set value=%s where name=%s'" %(cscfg.mgtSvr[0].port, 'integration.api.port') )
            # Open up 8096 for Marvin initial signup and register
            ssh.execute("service cloud-management restart")
    else:
        raise Exception("Reqd services (ssh, mysql) on management server are not up. Aborting")

    if _isPortListening(host=mgmt_host, port=8096, timeout=-1) and _isPortListening(host=mgmt_host, port=8080, timeout=-1):
        logging.info("All reqd services are up on the management server")
    else:
        raise Exception("Reqd services (apiport, systemport) on management server are not up. Aborting")

    logging.info("All systems go!")
