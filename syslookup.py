#Lookups for DHCP and IPMI addresses
ipmitable = {
    #by ip
    "10.223.75.2": "10.223.103.86",
    "10.223.75.20": "10.223.103.87",
    "10.223.75.9": "10.223.103.99",
    "10.223.78.20": "10.223.103.96",

    #by fqdn
    "infra": "10.223.103.86",
    "acs-qa-h11": "10.223.103.87",
    "acs-qa-h20": "10.223.103.96",
    "acs-qa-h21": "Unknown",
    "acs-qa-h23": "Unknown",
}

#Basically lists entire dhcp table
mactable = {
    "infra" : {
        "ethernet" : "9e:40:7d:09:f2:ef",
        "password" : "password",
        "address" :  "10.223.75.10"
    },

    "infraxen" : {
        "ethernet" : "d0:67:e5:ef:e0:69",
        "password" : "password",
        "address" :  "10.223.75.2"
    },

    "cloudstack-rhel": {
        "ethernet" : "b6:c8:db:33:72:41",
        "password" : "password",
        "address" : "10.223.75.41"
    },

    "cloudstack-ubuntu": {
        "ethernet" : "b6:c8:db:33:72:42",
        "password" : "password",
        "fixed-address" : "10.223.75.42"
    },

    "jenkins": {
        "ethernet": "b6:c8:db:33:72:43",
        "password" : "password",
        "address" : "10.223.75.43"
    },

    "acs-qa-h11": {
        "ethernet": "d0:67:e5:ef:e0:1b",
        "password" : "password",
        "address" : "10.223.75.20"
    },

    "acs-qa-h20": {
        "ethernet": "d0:67:e5:ef:e0:ff",
        "password" : "password",
        "address" : "10.223.78.20"
    },

    "acs-qa-h21": {
        "ethernet": "d0:67:e5:ef:e0:2d",
        "password" : "password",
        "address" : "10.223.78.140"
    },

    "acs-qa-h23": {
        "ethernet": "d0:67:e5:f1:b1:36",
        "password" : "password",
        "address" : "10.223.75.21"
    },

    "acs-qa-jenkins-slave": {
        "ethernet": "9e:2f:91:31:f4:8d",
        "password" : "password",
        "address" : "10.223.75.11"
    },
}
