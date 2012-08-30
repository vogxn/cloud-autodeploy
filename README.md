#Cloud AutoDeploy

Scripts here are used to refresh the builds of the management server with those
made out of our CI system. The CI system is internal at the moment.

###Dependencies
* Python
* [jenkinsapi](http://pypi.python.org/pypi/jenkinsapi)
* marvin

build.cfg - contains build information given to the CI system
        - branch, BUILDABLE_TARGET
        - distro of mgmt server tarball

You may leave the rest as they are defaults and should work fine.

environment.cfg - typically the VM where you intended to install above build of
mgmt server. SSH access to be available and credentials are in the config file.

deployment.cfg - the JSON network model configuration file generated by Marvin so
the mgmt server can be configured. See the Marvin tutorial on how to fetch these.

other options - skip-host - will skip IPMI/PXE refresh of the hosts
        - install-marvin - will pull the latest marvin tarball from the CI
          system and install it

Once you have the available configuration setup in the above .cfg files simply
run the following.

### 1a. reset the environment with the new build
`$ python configure.py -b build.cfg -e environment.cfg -d deployment.cfg [[--skip-host] --install-marvin]`

OR 

### b. reset the environment with specific build number
`$ python configure.py -n <build-number> -e environment.cfg -d deployment.cfg [[--skip-host] --install-marvin]`

### 2. restart mgmt server to have the integration port (8096) open
`$ python restartMgmt.py -e environment.cfg`

### 3. setup cloudstack with your deployment configuration
`$ nosetests -v --with-marvin --marvin-config=deployment.cfg --result-log=result.log -w /tmp`

### 4. restart again for global settings to be applied
`$ python restartMgmt.py -e environment.cfg`

### 5. wait for templates and system VMs to be ready
`$ nosetests -v --with-marvin --marvin-config=deployment.cfg --result-log=result.log testSetupSuccess.py`
