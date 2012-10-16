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

def configureManagementServer(mgmt_host, mgmtQueue):
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

    logging.debug("started mgmt VM with uuid: %s. Waiting for services .."%out[1]);
    mgmtWorker = threading.Thread(name="MgmtRefresh",
                                  target=attemptSshConnect, args =
                                  ([],mgmtQueue,))
    mgmtWorker.setDaemon(True)
    mgmtWorker.start()
    mgmtQueue.put(mgmt_host)

def _openIntegrationPort(csconfig):
    dbhost = csconfig.dbSvr.dbSvr
    dbuser = csconfig.dbSvr.user
    dbpasswd = csconfig.dbSvr.passwd
    logging.debug("opening the integration port on %s for %s with passwd %s"%(dbhost, dbuser, dbpasswd))
    conn = dbConnection.dbConnection(dbhost, 3306, dbuser, dbpasswd, "cloud")
    uquery = "update configuration set value=%s where name='integration.api.port'"%csconfig.mgtSvr[0].port
    conn.execute(uquery)
    squery = "select name,value from configuration where name='integration.api.port'"
    logging.debug("integration port open: "%conn.execute(squery))
       
def mountAndClean(host, path):
    mnt_path = "/tmp/" + ''.join([random.choice(string.ascii_uppercase) for x in xrange(0, 10)])
    mkdirs(mnt_path)
    logging.info("cleaning up %s:%s" % (host, path))
    mnt = bash("mount -t nfs %s:%s %s" % (host, path, mnt_path))
    erase = bash("rm -rf %s/*" % mnt_path)
    umnt = bash("umount %s" % mnt_path)
   
def cleanPrimaryStorage(cscfg):
    for zone in cscfg.zones:
        for pod in zone.pods:
            for cluster in pod.clusters:
                for primaryStorage in cluster.primaryStorages:
                    if urlparse.urlsplit(primaryStorage.url).scheme == "nfs":
                        mountAndClean(urlparse.urlsplit(primaryStorage.url).hostname, urlparse.urlsplit(primaryStorage.url).path)

def seedSecondaryStorage(cscfg, hypervisor):
    """
    erase secondary store and seed system VM template via puppet
    """
    mgmt_server = cscfg.mgtSvr[0].mgtSvrIp
    logging.info("Found mgmtserver at %s"%mgmt_server)
    bash("rm -f /etc/puppet/modules/cloudstack/files/secseeder.sh")
    for zone in cscfg.zones:
        for sstor in zone.secondaryStorages:
            shost = urlparse.urlsplit(sstor.url).hostname
            spath = urlparse.urlsplit(sstor.url).path
            logging.info("seeding %s systemvm template on %s @ %s"%(hypervisor, shost, spath))
            bash("echo '/bin/bash redeploy.sh -s %s -h %s' >> /etc/puppet/modules/cloudstack/files/secseeder.sh"%(spath, hypervisor))
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
    _waitForHostReady(hostlist)

def refreshStorage(cscfg, hypervisor="xen"):
    cleanPrimaryStorage(cscfg)
    logging.info("Cleaned up primary stores")

def attemptSshConnect(ready, hostQueue, port=22):
    host = hostQueue.get()
    logging.debug("Attempting port=%s connect to host %s"%(port, host))
    while True:
        channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        channel.settimeout(20)
        try:
            err = channel.connect_ex((host, port))
        except socket.error, e:
            logging.debug("encountered %s retrying in 20s"%e)
            delay(20)
        finally:
            if err == 0:
                ready.append(host)
                logging.debug("host: %s is ready"%host)
                break
            else:
                logging.debug("[%s] host %s is not ready. Retrying"%(err, host))
                delay(20)
                channel.close()
    hostQueue.task_done()

def _waitForHostReady(hostlist):
    logging.info("Waiting for hosts to refresh")
    ready = []
    hostQueue = Queue.Queue()

    for host in hostlist:
        t = threading.Thread(name='HostWait-%s'%hostlist.index(host), target=attemptSshConnect,
                             args=(ready, hostQueue, ))
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
    mgmtQueue = Queue.Queue()

    cscfg = configGenerator.get_setup_config(auto_config)
    seedSecondaryStorage(cscfg, options.hypervisor)
    logging.info("Secondary storage seeded via puppet with systemvm templates")

    logging.info("Configuring management server")
    configureManagementServer(mgmt_host, mgmtQueue)

    if not options.skip_host:
        refreshHosts(cscfg, options.hypervisor, options.profile)

    mgmtQueue.join()
    delay(120) #problems when communicating with mysql port are resolved by this delay
    _openIntegrationPort(cscfg)
    refreshStorage(cscfg, options.hypervisor)
    logging.info("All systems go!")
