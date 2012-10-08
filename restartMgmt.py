from ConfigParser import ConfigParser
from optparse import OptionParser
import marvin
from marvin import configGenerator
from marvin import remoteSSHClient
from time import sleep as delay

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-c", "--config", action="store", default="xen.cfg",
                      dest="config", help="the path where the server configurations is stored")
    (options, args) = parser.parse_args()
    
    if options.config is None:
        raise

    cscfg = configGenerator.get_setup_config(options.config)
    mgmt_server = cscfg.mgtSvr[0].mgtSvrIp
    ssh = remoteSSHClient.remoteSSHClient(mgmt_server, 22, "root", "password")
    ssh.execute("service cloud-management restart")
    delay(120)
