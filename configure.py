from ConfigParser import ConfigParser
from bashUtils import bash
from buildGenerator import BuildGenerator
from marvin import configGenerator
from marvin import remoteSSHClient
from marvin import dbConnection
from optparse import OptionParser
from ipmi_lookup import ipmitable
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

SRC_ARCH_DIR = "/root/cloud/arch"
DST_ARCH_DIR = "/root/cloud/arch"
WORKSPACE = "." #Where redeploy.sh is placed. Ideally repo home

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

def build(build_config, build_number, job):   
    hudson = BuildGenerator(job=job)
    if build_config is not None:
        hudson.readBuildConfiguration(build_config)
        if hudson.build():
         return hudson
        else:
         raise EnvironmentError("hudson build failed")
    elif build_number is not None and build_number > 0:
        bld = hudson.getBuildWithNumber(int(build_number))
        if bld is not None:
            return hudson
        else: 
            raise EnvironmentError("Could not find build with number %s"%build_number)


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

def copyBuildToMshost(hudson, env_config):
   cfg = ConfigParser()
   cfg.optionxform = str
   cfg.read(env_config)
   
   environment = dict(cfg.items('environment'))
   ssh = remoteSSHClient.remoteSSHClient(environment['mshost.ip'], 22, environment['mshost.username'], environment['mshost.password'])
   ssh.execute("mkdir -p %s" % DST_ARCH_DIR)
   
   src_path = os.path.join(SRC_ARCH_DIR, hudson.getTarballName())
   dst_path = os.path.join(DST_ARCH_DIR, hudson.getTarballName())
   logging.debug("copying CS tarball from %s to %s"%(src_path, dst_path))
   ssh.scp("%s" % src_path, "%s" % dst_path)
   logging.info("%s has been copied to the automation instance %s under %s" % (hudson.getTarballName(), environment['mshost.ip'], DST_ARCH_DIR))
   
   return dst_path
   
def configureManagementServer(bld, env_config, auto_config):
    tarball_path = copyBuildToMshost(bld, options.env_config)
    cfg = ConfigParser()
    cfg.optionxform = str
    cfg.read(env_config)
    environment = dict(cfg.items('environment'))
    cscfg = configGenerator.get_setup_config(auto_config)
    
#    1. erase secondary store
#    2. seed system VM template
#    3. setup-databases and setup-management
    ssh = remoteSSHClient.remoteSSHClient(environment['mshost.ip'], 22, environment['mshost.username'], environment['mshost.password'])
    ssh.scp("%s/redeploy.sh" % WORKSPACE, "/root/redeploy.sh")
    ssh.execute("chmod +x /root/redeploy.sh")
    for zone in cscfg.zones:
        for sstor in zone.secondaryStorages:
            shost = urlparse.urlsplit(sstor.url).hostname
            spath = urlparse.urlsplit(sstor.url).path
#            ssh.execute_buffered("bash redeploy.sh -s %s -a %s -d %s"%(spath, tarball_path, cscfg.dbSvr.dbSvr))
            bash("ssh -ostricthostkeychecking=no -oUserKnownHostsFile=/dev/null %s@%s bash redeploy.sh -s %s -a %s -d %s"%(environment['mshost.username'], environment['mshost.ip'], spath, tarball_path, cscfg.dbSvr.dbSvr))
            
    delay(120)
    _openIntegrationPort(cscfg, env_config)
    cleanPrimaryStorage(cscfg)

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

def savebuild(hudson):  
    tarball_url = "http://%s" % hudson.resolveRepoPath()
    fetch(hudson.getTarballName(), tarball_url, SRC_ARCH_DIR)
    logging.info("build %s saved under %s" % (hudson.getTarballName(), SRC_ARCH_DIR))
    
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
    mkdirs(SRC_ARCH_DIR)
    mkdirs(WORKSPACE)
        
if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-b", "--build-config", action="store", default=None, dest="build_config", help="the path where the configuration of the build is stored")
    parser.add_option("-e", "--env-config", action="store", default="environment.cfg", dest="env_config", help="the path where the server configurations is stored")
    parser.add_option("-d", "--deployment-config", action="store", default="automation.cfg", dest="auto_config", help="json spec of deployment")
    parser.add_option("-n", "--build-number", action="store", default=None, dest="build_number", help="CloudStack build number")
    parser.add_option("-s", "--skip-host", action="store_true", default=False, dest="skip_host", help="Skip Host Refresh")
    parser.add_option("-m", "--install-marvin", action="store_true", default=True, dest="install_marvin", help="Install Marvin")
    (options, args) = parser.parse_args()

    if options.build_number is None and options.build_config is None:
        raise AttributeError("must provide a configuration file for the build or a build number")
    if options.build_config is not None and options.build_number is not None:
        raise AttributeError("either build.cfg is provided or the build number - not both")
        
    if options.env_config is None:
        raise AttributeError("please provide the server configuration file")
    
    if options.auto_config is None:
        raise AttributeError("please provide the spec file for your deployment")

    init()
    
    bld = build(options.build_config, options.build_number, "CloudStack-PRIVATE")
    savebuild(bld)
    configureManagementServer(bld, options.env_config, options.auto_config)
    if not options.skip_host:
        refreshHosts(options.auto_config)

    if not options.install_marvin:
        if options.build_config:
            bld = build(options.build_config, 0, "marvin-testclient")
            for k, v in bld.getArtifacts().iteritems(): 
                fetch(k, v.url, SRC_ARCH_DIR)
                bash("pip uninstall -y marvin")
                bash("pip install %s/%s"%(SRC_ARCH_DIR, k))
