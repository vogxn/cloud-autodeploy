from ConfigParser import ConfigParser
from bashUtils import bash
from buildGenerator import BuildGenerator
from marvin import configGenerator
from marvin import remoteSSHClient
from marvin import dbConnection
from optparse import OptionParser
from syslookup import ipmitable
from syslookup import mactable
from time import sleep as delay
import bashUtils
import buildGenerator
import logging
import marvin
import os
import random
import string
import urllib2
import urlparse
import socket
import select
import errno

WORKSPACE="/root"

def initLogging(logFile=None, lvl=logging.INFO):
    try:
        if logFile is None:
            logging.basicConfig(level=lvl, \
                                format="'%(asctime)-6s: %(name)s - %(levelname)s - %(message)s'") 
        else: 
            logging.basicConfig(filename=logFile, level=lvl, \
                                format="'%(asctime)-6s: %(name)s - %(levelname)s - %(message)s'") 
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

def configureManagementServer(auto_config, mgmt_host):

    mgmt_vm = mactable[mgmt_host]
    #Remove and re-add cobbler system
    bash("cobbler system remove --name=%s"%mgmt_host)
    bash("cobbler system add --name=%s --hostname=%s --mac-address=%s \
         --netboot-enabled=yes --enable-gpxe=no \
         --profile=%s"%(mgmt_host, mgmt_host, mgmt_vm["ethernet"], mgmt_host));

    #Revoke all certs from puppetmaster
    bash("puppet cert clean %s.cloudstack.org"%mgmt_host)

    #Start VM on xenserver
    xenssh = \
    remoteSSHClient.remoteSSHClient(mactable["infraxen"]["address"],
                                    22, "root",
                                    mactable["infraxen"]["password"])

    logging.debug("bash vm-start.sh -n %s -m %s"%(mgmt_host, mgmt_vm["ethernet"]))
    out = xenssh.execute("bash vm-start.sh -n %s -m %s"%(mgmt_host,
                                                  mgmt_vm["ethernet"]))

    logging.debug("started VM with uuid: %s"%out[1]);

#    cscfg = configGenerator.get_setup_config(auto_config)
    
#    1. erase secondary store
#    2. seed system VM template
#    3. setup-databases and setup-management
#    ssh = remoteSSHClient.remoteSSHClient(environment['mshost.ip'], 22, environment['mshost.username'], environment['mshost.password'])

    #FIXME: For Ubuntu
#    ssh.scp("%s/redeploy.sh" % WORKSPACE, "/tmp/redeploy.sh")
#    ssh.execute("chmod +x /tmp/redeploy.sh")
#    for zone in cscfg.zones:
#        for sstor in zone.secondaryStorages:
#            shost = urlparse.urlsplit(sstor.url).hostname
#            spath = urlparse.urlsplit(sstor.url).path
#            bash("ssh %s@%s bash /tmp/redeploy.sh -s %s -d %s"%(environment['mshost.username'], environment['mshost.ip'], spath, cscfg.dbSvr.dbSvr))

#    delay(120)

## TODO: Use Puppet for this
def _openIntegrationPort(csconfig, env_config):
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

def refreshHosts(auto_config):
    hostlist = []
    cscfg = configGenerator.get_setup_config(auto_config)
    for zone in cscfg.zones:
        for pod in zone.pods:
            for cluster in pod.clusters:
                for host in cluster.hosts:
                    hostname = urlparse.urlsplit(host.url).hostname
                    hostlist.append(hostname)
                    logging.debug("attempting to refresh host %s"%hostname)
                    ipmi_hostname = ipmitable[hostname]
                    #set ipmi to boot from PXE
                    if ipmi_hostname is not None:
                        logging.debug("found IPMI nic on %s for host %s"%(ipmi_hostname, hostname))
                        bash("ipmitool -Uroot -Pcalvin -H%s chassis bootdev pxe"%ipmi_hostname)
                        bash("ipmitool -Uroot -Pcalvin -H%s chassis power cycle"%ipmi_hostname)           
                        logging.debug("Sent PXE boot for %s"%ipmi_hostname)
                        delay(30)
                    else:
                        logging.warn("No ipmi host found against %s"%hostname)
    cleanPrimaryStorage(cscfg)
    logging.info("Cleaned up primary stores")

    logging.info("Waiting for hosts to refresh")
    _waitForHostReady(hostlist)

def _waitForHostReady(hostlist):
    #TODO:select on ssh channel for all hosts
    ready = []
    
    for host in hostlist:
        remain = list(set(hostlist) - set(ready))
        while len(remain) != 0:
            channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            channel.settimeout(20)
            #double try older pythons
            try:
                try:
                    err = channel.connect_ex((host, 22))
                except socket.error, e:
                        logging.debug("encountered %s retrying in 20s"%e)
                        delay(20)
            finally:
                if err == 0:
                    ready.append(host)
                    logging.debug("host: %s is ready"%host)
                    break #socket in to next host
                else:
                    logging.debug("[%s] host %s is not ready"%(err, host))
                    delay(20)
                channel.close()
        logging.debug("hosts still remaining: %s"%remain) 
    

def init():
    initLogging()
        
if __name__ == '__main__':
    init()

    parser = OptionParser()
    parser.add_option("-v", "--hypervisor", action="store", default="xen",
                      dest="hypervisor", help="hypervisor type")
    parser.add_option("-d", "--distro", action="store", default="rhel",
                      dest="distro", help="management server distro")
    parser.add_option("-s", "--skip-host", action="store_true", default=False,
                      dest="skip_host", help="Skip Host Refresh")
    (options, args) = parser.parse_args()

    if options.hypervisor == "xen":
        auto_config = "xen.cfg"
    elif options.hypervisor == "kvm":
        auto_config = "kvm.cfg"
    else:
        auto_config = "xen.cfg"

    mgmt_host = "cloudstack-"+options.distro

    logging.info("configuring %s for hypervisor %s"%(mgmt_host,
                                                     options.hypervisor))
    configureManagementServer(auto_config, mgmt_host)
#    if not options.skip_host:
#sysl        refreshHosts(options.auto_config)
