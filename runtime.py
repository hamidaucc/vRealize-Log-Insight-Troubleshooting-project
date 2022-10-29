#!/usr/bin/python3
'''
  auther @ hamid A
  For GSS troubleshooting
  Any advice or Error, contact: haabdul@vmware.com
'''

import re
import os
import subprocess as sp
import datetime

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[39m"

#logFilename = os.path.abspath("/storage/var/loginsight/upgrade.log")

path = "/storage/core/loginsight/var/"

applicationPath = "/usr/lib/loginsight/application"

nodesPath = os.path.join(path, "/cidata/cassandra/config", "cassandra.yaml")
versionOut = []


# sed -n "1,10p" /storage/core/loginsight/config/loginsight-config.xml#* | cat. can save as list and pull out worker nodes too
# os.system('sed -n "1,10p" /storage/core/loginsight/config/loginsight-config.xml#* | cat')

def outline():
    print(">>>>" * 30)

def commonsinfo():
    # y=[print((">>"*15),os.system(i))  for i in x ]
    # systemctl status  iptables
    print("\t\t", GREEN + "Basic network info :" + RESET)
    now = datetime.datetime.now()
    print(OKGREEN+"Current server time"+ RESET)
    print(now)
    print()
    ifconfig = sp.getoutput("ifconfig")
    print(OKGREEN + "IP,Bcast,Subnet Mask: "+ RESET)
    print(ifconfig)
    print()
    y = sp.getoutput("cat /proc/cpuinfo")
    print(OKGREEN + "CPU info: " + RESET)
    print(y)
    print()
    print(OKGREEN + "UP Time: " + RESET)
    p = sp.getoutput("uptime")
    print(p)
    print()
    hostname = sp.getoutput("hostname")
    print(OKGREEN + "Host Name or FQDN : " + RESET)
    print(hostname)
    print()
    hosts = sp.getoutput("cat /etc/hosts")
    print(OKGREEN + "DNS set up : " + RESET)
    print(hosts)
    print()
    ntp = sp.getoutput("systemctl status  systemd-timesyncd")
    print(OKGREEN + "NTP Status: " + RESET)
    print(ntp)
    print()
    route=sp.getoutput("ip route")
    print(OKGREEN + "Routing: " + RESET)
    print(route)
    arp=sp.getoutput("ip neighbour")
    print(OKGREEN + "Listening Neighbour: " + RESET)
    print(arp)

    # commonCommands = ["cat /proc/cpuinfo", "ifconfig", "hostname",
    #                   "cat /etc/resolv.conf"]
    # for i in commonCommands:
    #     print("")
    #     os.system(i)
    #     print()
    #     print()


def dnsinfo():
    print(GREEN + "DNS name server info :" + RESET)
    dns = sp.getoutput("tail /etc/resolv.conf")
    # print(y[-1])
    print(dns)
    print()


def openports():
    print( GREEN + "List of listening ports:" + RESET)
    print()
    x = " ss -tulpn | grep LISTEN" # Ref: https://vmware.github.io/photon/assets/files/html/3.0/photon_troubleshoot/inspecting-ip-addresses.html
    os.system(x)


def diskspace():
    print("\t\t", GREEN + "Disk space info:" + RESET)
    print()
    x = "df -h"
    y=os.system(x)
    print(y)
    print(GREEN + "Root space info:" + RESET)
    k = sp.getoutput("du -ahx / | sort -rh | head -n 20")
    print(k)


def version():
    '''
    \d* - any number of digits

    \. - a dot

    \d* - more digits.
    '''
    print("\t\t", GREEN + "Current Version:" + RESET)
    output = sp.getoutput("cat /etc/vmware/.buildInfo")
    p = r"\d\.\d\.\d"  # \d* - any number of digits
    z = re.findall(p, output)
    t = (".".join(z))  # v=str(z)[1:-1]
    print(f"Current LI version: {t}")


def cacert():
    x = "openssl x509 -noout -enddate -in /storage/core/loginsight/cidata/cassandra/config/cacert.pem"
    p = "/opt/vmware/bin/li-ssl-cert.sh --check"

    print("\t\t", GREEN + "Validity of certificate:" + RESET)
    os.system(x)
    print("Certificate info: ")
    os.system(p)


def casaanalysis():
    print("\t\t", GREEN + "Cassandra Log:" + RESET)
    print()
    cass_count = 0
    # cassPath = os.path.join(path, "cassandra.log")
    cassPath = os.path.join(path, "demo_cassandra.log")#just for demo
    cassError = ["Unable to gossip with any seeds", "Too many open files", "Hints Descriptor CRC Mismatch",
                 "Failed to dispatch hints", "Cassandra server running in degraded mode",
                 "Unable to verify sstable files on disk","Unable to gossip with any peers"
                 ," Harmless error reading saved cache", "Cannot start multiple repair sessions over the same sstables"
                 ,"SSL handshake error for outbound connection","Setup task failed with error","CassandraRoleManager skipped default role setup",
                 ]
    with open(cassPath, "r") as F1:
        for i in F1:
            for y in cassError:
                if re.search(y, i):
                    cass_count += 1
                    print(i)
    # print(f"Total Appeared: {cass_count}")
    print()
def upgradeanalysis():
    print("\t\t", GREEN + "Upgrade Log:" + RESET)
    print()
    print( RED+ "Working in progress"+ RESET)

def runanalysis():
    print("\t\t", GREEN + "Run time log:" + RESET)
    print()
    # runPath = os.path.join(path, "runtime.log")
    runPath = os.path.join(path, "demo_runtime.log") # Just for demo
    runCount = 0
    runError = ["keystore does not exist", "Cassandra failed to start", "Exception during start cassandra database",
                "Daemon startup failed", "Remote host closed connection during handshake",
                "All host(s) tried for query failed", "Received fatal alert: internal_error","Unable to validate Active Directory credentials",
                "com.vmware.loginsight.commons.exceptions.AuthenticationException","com.vmware.loginsight.aaa.krb5.KrbAuthenticator",
                "Failed to connect to LDAP server","Kerberos login in 110146ms","No route to host",
                "Authentication error on host",]
    with open(runPath, "r") as F3:
        for i in F3:
            for word in runError:
                if re.search(word, i):
                    print(i)
                    runCount += 1
    # print(f"From runtime.log: {runCount}")


def ui_run():
    print("\t\t", GREEN + "User Interface Run time log:" + RESET)
    print()
    uiCount = 0
    # uiPath = os.path.join(path, "ui_runtime.log")
    uiPath = os.path.join(path, "demo_ui_runtime.log")#Just for demo
    uiError = ["Error creating SSL socket factory", "javax.net.ssl.SSLHandshakeException",
               "Remote host closed connection during handshake",
               "problem accessing trust store", "java.security.KeyStoreException", "problem accessing trust store",
               "NFS test failed","Socket is closed by peer","Unable to validate Active Directory credentials",
               "Caused by: KrbException: Server not found in Kerberos database",]
    commonError=""
    genericError=""
    with open(uiPath, "r") as F2:
        for line in F2:
            for word in uiError:
                if re.search(word, line):
                    commonError += line
            if re.search("ERROR" or "error" or "ERROR]" or "ERROR ]", line):
                genericError += line

            # if ("ERROR" or "error" or "ERROR]") in line:
            #     genericError += line

            # for common in error:
            #     if re.findall(common,line):
            #         print(line)
            #         print()
    print(RED + "Commom Error" + RESET)
    print(commonError)
    print()
    print(RED + "Generic Error" + RESET)
    print(genericError)
    # print(f"From ui_runtime.log: {uiCount}")


def systemalert():
    print("\t\t", GREEN + "System Alert log:" + RESET)
    print()
    try:

        # systematical = os.path.join(path, "systemalert.log")#Just for demo
        systematical = os.path.join(path, "demo_systemalert.log")  # Just for demo
        total = 0
        alert = ["Error creating SSL socket factory", "vCenter collection failed triggered",
                 "vCenter Kubernetes Service event collection failed","The worker node sending this alert was unable to contact the leader node"
                 "Failed to verify current upgrade status","Daemon startup failed: Failed to start Tomcat",
                 "Worker node disconnected"]
        with open(systematical, "r") as F1:
            for i in F1:
                for word in alert:
                    if re.search(word, i):
                        print(i)
                        total += 1

        # print(f"From system alert.log: {total}")
    except:
        print("Ops no common error")


# It's for latest LI i.e 8.4 and above
def cassandrastatus():
    print("\t\t", GREEN + "Cassandra Status :" + RESET)
    print()
    x = 0
    # x="/usr/lib/loginsight/application/lib/apache-cassandra-*/bin/nodetool-no-pass status"
    password = sp.getoutput("/usr/lib/loginsight/application/lib/apache-cassandra-*/bin/credentials-look-up")
    statusWithLatest = os.path.join(applicationPath, "lib/apache-cassandra-*/bin/nodetool-no-pass status")
    status = os.path.join(applicationPath, "lib/apache-cassandra-*/bin/nodetool status")
    statusWithpassword = os.path.join(applicationPath, "lib/apache-cassandra-*/bin/nodetool -u lisuper -pw "" status")
    try:
        if x < 1:
            os.system(statusWithLatest)
        else:
            os.system(status)  # need to check with lisuper and -pw with password

    except ValueError as v:
        print()
        print(RED + "Cassandra connection is not possible" + RESET)
    # nodesPath=os.path.join(path,"/cidata/cassandra/config", "cassandra.yaml")
    # os.system(nodesPath)


# Suggested upload from @Joanna
# check in the logs previous upgrades usr/lib/loginsight/applications/etc/migrations
# check in the logs content pack installed usr/lib/loginsight/applications/etc/content_packs
def versionfrom():
    """

    @rtype: object
    """
    print("\t\t", GREEN + "Version history:" + RESET)
    print()
    versionPath = os.path.join(applicationPath, "etc/migrations", "changelog.xml")
    with open(versionPath, "r") as x:
        for line in x:
            if re.search("include file", line):
                # versionOut.append(line)
                print(line)


def totalnode():
    print("\t\t", GREEN + "Cluster info:" + RESET)
    print()
    nodesPath = "/storage/core/loginsight/cidata/cassandra/config/cassandra.yaml"
    with open(nodesPath, "r") as nodes:
        for line in nodes:
            if re.search("seeds", line):
                print(line[1::])



def node():
    with open("/storage/core/loginsight/cidata/cassandra/config/cassandra.yaml") as F1:
        data = yaml.load(F1, Loader=SafeLoader)
        for i in data:
            print("Main file", i)
            if re.search("seeds", i, re.MULTILINE):
                print(i)


def agentanalysis():
    print("\t\t", GREEN + "Agent logs:" + RESET)
    print()
    # /var/log/loginsight-agent
    commonError = [""]
    print(RED+ "Working in progress" + RESET)


# os.system("clear")


def vSpherelog():
    print("\t\t", GREEN + "vSphere Log:" + RESET)
    print()
    # storage/core/loginsight/var/plugins/vsphere/li-vsphere.log
    commonError = ["Error running vSphere WCP collection", "[IP of vCenter] ERROR", "Failed to Monitor VimEvents"]
    print()
    print( RED+ "Working in progress" + RESET)


#


if __name__ == '__main__':
    #os.system("clear")
    commonsinfo()
    openports()
    dnsinfo()
    diskspace()
    version()
    #versionfrom()
    totalnode()
    cassandrastatus()
    outline()
    cacert()
    casaanalysis()
    runanalysis()
    upgradeanalysis()
    ui_run()
    systemalert()
    agentanalysis()
    vSpherelog()
