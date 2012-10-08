#Isolate the run into a virtualenv
virtualenv-2.7 -p /usr/local/bin/python2.7 acs-nightly-tests-$BUILD_NUMBER

#Copy the tests into the virtual env
rsync -avz test acs-nightly-tests-$BUILD_NUMBER/
cd acs-nightly-tests-$BUILD_NUMBER

## Start
source bin/activate

#Setup Test Data
bash -x test/setup-test-data.sh -t test/integration/smoke -m 10.223.133.41 -p password -d 10.223.133.41
if [[ $? -ne 0 ]]; then
    echo "Problem seeding test data"
    exit 2
fi

#Get Marvin and install
tar=$(wget -O - http://jenkins.cloudstack.org:8080/job/build-marvin-4.0/lastSuccessfulBuild/artifact/tools/marvin/dist/ | grep Marvin |  sed -e :a -e 's/<[^>]*>//g;/</N;//ba' | sed -e 's/[ \t]*//g' | cut -d"z" -f1)'z'
url='http://jenkins.cloudstack.org:8080/job/build-marvin-4.0/lastSuccessfulBuild/artifact/tools/marvin/dist/'$tar
wget $url
pip install $tar

#Install marvin-nose plugin
pip install lib/python2.7/site-packages/marvin/


#Deploy the configuration
if [[ $DEPLOY -eq "yes" ]]; then
    #Kick off environment refresh
    git clone https://github.com/vogxn/cloud-autodeploy.git
    cd cloud-autodeploy
    git checkout acs-infra-test

    if [[ $hypervisor -eq 'xen' ]];then
        profile='xen602'
    else
        profile='rhel63-kvm'
    fi

    python configure.py -v $hypervisor -d $distro -p $profile
    #Restart to open up integration ports
    python ../cloud-autodeploy/restartMgmt.py --config ../cloud-autodeploy/$hypervisor.cfg
    cd ../test
    nosetests -v --with-marvin --marvin-config=../cloud-autodeploy/$hypervisor.cfg -w /tmp
    #Restart to apply global settings
    python ../cloud-autodeploy/restartMgmt.py --config ../cloud-autodeploy/$hypervisor.cfg

    #Health Check
    nosetests -v --with-marvin --marvin-config=../cloud-autodeploy/$hypervisor.cfg --load ../cloud-autodeploy/testSetupSuccess.py
fi

if [[ $DEBUG -eq "yes" ]]; then
    nosetests -v --with-marvin --marvin-config=../cloud-autodeploy/$hypervisor.cfg -w integration/smoke --load --with-xunit --collect-only
else
    nosetests -v --with-marvin --marvin-config=../cloud-autodeploy/$hypervisor.cfg -w integration/smoke --load --with-xunit
fi

#deactivate and exit
deactivate
