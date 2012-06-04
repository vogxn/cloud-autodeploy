from ConfigParser import ConfigParser
from optparse import OptionParser
import marvin
from marvin import remoteSSHClient
from time import sleep as delay

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-e", "--env-config", action="store", default="environment.cfg", dest="env_config", help="the path where the server configurations is stored")
    (options, args) = parser.parse_args()
    
    if options.env_config is None:
        logging.error("please provide the server configuration file")
        raise

    cfg = ConfigParser()
    cfg.optionxform = str
    cfg.read(options.env_config)
    environment = dict(cfg.items('environment'))

    mgmt_ssh = remoteSSHClient.remoteSSHClient(environment['mshost.ip'], 22, environment['mshost.username'], environment['mshost.password'])
    mgmt_ssh.execute("service cloud-management restart")
    delay(120)
