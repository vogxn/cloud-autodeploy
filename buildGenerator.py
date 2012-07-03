#!/usr/bin/env python

from ConfigParser import ConfigParser
from jenkinsapi import api, jenkins, job
from time import sleep as delay
import jenkinsapi
import logging
import os
from jenkins import JenkinsException

class BuildGenerator(object):
    """
    1. Create a job on Hudson/Jenkins 
    2. Poll for job status
    3. Fetch latest successful job
    4. Resolve Job to Repo URL/fetch artifact
    """
    def __init__(self, username=None, passwd=None, url="http://hudson.lab.vmops.com", job='CloudStack'):
        #TODO: Change the username to "vogon" for automation
        self.hudsonurl = url
        self.tarball = None
        self.build_number = 0
        #self.jenkinsurl = "http://jenkins.jobclient.org"
        if username and passwd:
            self.username = username
            self.password = passwd
        else:
            logging.warning("no username given, logging in with default creds")
            self.username = "marvin"
            self.password = "marvin"

        try:
            j = jenkins.Jenkins(self.hudsonurl, self.username, self.password)
            self.jobclient = j.get_job(job)
        except Exception, e:
            logging.error("Failed to login to Hudson")
            raise e
        else:
            logging.debug("successfully logged into hudson instance %s \
                          using username, passwd : %s, %s" \
                          %(self.hudsonurl, self.username, self.password))

    def readBuildConfiguration(self, cfg_file):
        cfg = ConfigParser()
        cfg.optionxform = str
        if cfg.read(cfg_file):
            logging.debug("Using config file found at %s"%cfg_file)
            self.config = cfg
        else:
            raise IOError("Cannot find file %s"%cfg_file)

    def parseConfigParams(self):
        #TODO: passing a config file should be allowed as cmd line args
        params = {}
        if self.config:
            logging.debug("build params found:")
            for k,v in dict(self.config.items('build_params')).iteritems():
                logging.debug("%s : %s"%(k,v))
            return dict(self.config.items('build_params'))
        else:
            logging.debug("build config not found")
            raise ValueError("Build configuration was not initialized")

    def build(self, wait=60):
        if self.config and self.jobclient:
            self.jobclient.invoke(params=self.parseConfigParams())
            self.build_number = self.jobclient.get_last_buildnumber()
            self.paramlist = self.parseConfigParams()
            logging.debug("Started build : %d"%self.jobclient.get_last_buildnumber())
            while self.jobclient.is_running():
                logging.debug("Polling build status in %ss"%wait)
                delay(wait)
            logging.debug("Completed build : %d"%self.jobclient.get_last_buildnumber())
            if self.jobclient.get_last_completed_buildnumber() == self.build_number \
            and self.jobclient.get_last_completed_buildnumber() == self.jobclient.get_last_good_buildnumber():
                return self.build_number
            elif self.jobclient.get_last_completed_buildnumber() > self.build_number:
                logging.debug("Overtaken by another build. Determining build status for %d"%self.build_number)
                our_build = self.getBuildWithNumber(self.build_number)
                if our_build is not None and our_build.get_status() == 'SUCCESS':
                    return self.build_number
            else:
                return 0

    def getLastGoodBuild(self):
        return self.jobclient.get_build(self.build_number)
    
    def getBuildWithNumber(self, number):
        if number > 0:
            bld = self.jobclient.get_build(number)
            self.build_number = number
            self.paramlist = self.getBuildParamList(bld)
            return bld

    def getBuildParamValue(self, name):
        return self.paramlist[name]

    def getTarballName(self):
        if self.tarball is not None:
            return self.tarball
        else:
            self.resolveRepoPath()
            return self.getTarballName()
    
    def getArtifacts(self):
        artifact_dict = self.getLastGoodBuild().get_artifact_dict()
        if artifact_dict is not None:
            return artifact_dict

    def sift(self, dic):
        return dic['name'], dic['value']
    
    def getBuildParamList(self, bld):
        params = bld.get_actions()['parameters']
        return dict(map(self.sift, params))
        
    def resolveRepoPath(self):
            tarball_list = ['CloudStack-' , 
                       self.getBuildParamValue('PACKAGE_VERSION') , 
                       '-0.', str(self.build_number) , '-' , 
                       self.getBuildParamValue('DO_DISTRO_PACKAGES') ,  
                       '.tar.gz'] 

            self.tarball = ''.join(tarball_list)

            path = os.path.join('yumrepo.lab.vmops.com', 'releases', 'rhel', \
                                self.getBuildParamValue('DO_DISTRO_PACKAGES').strip('rhel'), \
                                self.getBuildParamValue('PUSH_TO_REPO'), \
                                self.tarball)
            logging.debug("resolved last good build generated by us to: %s"%path)
            return path

if __name__ == '__main__':
#    hudson = BuildGenerator(job="marvin")
#    hudson.readBuildConfiguration('build.cfg')
#    hudson.build()

     hudson = BuildGenerator("CloudStack")
     hudson.getBuildWithNumber(2586)
