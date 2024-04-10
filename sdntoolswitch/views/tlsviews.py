import os
import syslog
import paramiko

from django.shortcuts import redirect, render
from django.contrib import messages
from sdntoolswitch.activitylogs import *
from sdntoolswitch.onosseclogs import *
from sdntoolswitch.aaalogs import *

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

ipconfiglist = []

def modifytls(request):
    """
    View for modifying TLS
    """
    with open("iplist.txt", "r") as file:
        iplist = file.readlines()
    if request.method == "GET":
        return render(request, "sdntool/modifytls.html", {"ip": iplist})
    status = request.POST.get("status")
    keyloc = request.POST.get("keyloc")
    keypassword = request.POST.get("keypassword")
    trustloc = request.POST.get("trustloc")
    trustpassword = request.POST.get("trustpassword")
    ip = request.POST.get("ip")
    try:
        with open("userip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP is given as input")
        return redirect("modifytls")

    host = str(ip)
    port = 22
    username = request.POST.get("sshuser")
    password = request.POST.get("sshpass")
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)
    except:
        messages.error(request, "Unable to connect remotely")
        return redirect("home")
    # Create SFTP client
    sftp = ssh.open_sftp()
    try:
        onos_location = request.POST.get("fileloc")
        with sftp.open(f"{onos_location}/bin/onos-service", "r") as file:
            data = file.readlines()  ###### reading all lines

        for i in range(len(data)):
            if data[i].startswith("export JAVA_OPTS"):
                if status == "true":
                    enable_tls = "true"
                    messages.success(request, "Action Enabled")
                else:
                    enable_tls = "false"
                    messages.error(request, "Action Disabled")
                data[i] = (
                    "export JAVA_OPTS="
                    + '"'
                    + f"${{JAVA_OPTS:--DenableOFTLS={enable_tls} -Djavax.net.ssl.keyStore="
                    + str(keyloc)
                    + " -Djavax.net.ssl.keyStorePassword="
                    + str(keypassword)
                    + " -Djavax.net.ssl.trustStore="
                    + str(trustloc)
                    + " -Djavax.net.ssl.trustStorePassword="
                    + str(trustpassword)
                    + '}"'
                    + "\n"
                )
                break

        with sftp.open(f"{onos_location}/bin/onos-service", "w") as file:
            file.writelines(data)

        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to connect with given IP")
        return redirect("modifytls")

    with open("username.txt") as file:
        username = file.read()

    sec_log_call(f"{username} modified TLS")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} modified TLS")

    with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
        if os.stat("onossec.log").st_size != 0:
            lastline = firstfile.readlines()[-1].strip()
            secondfile.write(lastline + "\n")
            syslog.syslog(syslog.LOG_INFO, lastline)

    messages.success(request, "Action Enabled")
    messages.info(request, "TLS configuration modified")
    return redirect("viewtls")


def disabletls(request):
    return render(request, "sdntool/disabletls.html")


def disabletlsconfirm(request):
    """
    Controller for disabling TLS
    """
    with open("iplist.txt", "r") as file:
        iplist = file.readlines()
    if request.method == "GET":
        return render(request, "sdntool/disabletlsip.html", {"ip": iplist})
    ip = request.POST.get("ip")

    try:
        with open("userip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP is given as input")
        return redirect("disabletlsconfirm")

    host = str(ip)
    port = 22
    username = request.POST.get("sshuser")
    password = request.POST.get("sshpass")
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)
    except:
        messages.error(request, "Unable to connect remotely")
        return redirect("home")
    # Create SFTP client
    sftp = ssh.open_sftp()
    try:
        onos_location = request.POST.get("fileloc")
        with sftp.open(f"{onos_location}/bin/onos-service", "r") as file:
            data = file.readlines()  ###### reading all lines

        data[10] = data[10].replace("true", "false")
        with sftp.open(f"{onos_location}/bin/onos-service", "w") as file:
            file.writelines(data)
        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to connect with given IP")
        return redirect("disabletlsconfirm")

    messages.error(request, "TLS Disabled")
    messages.info(request, "TLS configured")
    with open("username.txt") as file:
        username = file.read()

    sec_log_call(f"{username} disabled TLS")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} disabled TLS")

    with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
        if os.stat("onossec.log").st_size != 0:
            lastline = firstfile.readlines()[-1].strip()
            secondfile.write(lastline + "\n")
            syslog.syslog(syslog.LOG_INFO, lastline)

    return redirect("viewtls")


def viewtls(request):
    """
    View for viewing TLS configuration
    """
    global ipconfiglist
    with open("userip.txt", "r") as file:
        ip = file.read()

    host = str(ip)
    port = 8101
    username = "karaf"
    password = "karaf"
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)
        outdata = errdata = b""
        ssh_trans = ssh.get_transport()
        ssh_trans.host_key_type = "ssh-rsa"
        chan = ssh_trans.open_session()
        chan.setblocking(0)
        chan.exec_command("cat ../bin/onos-service")
        while True:
            while chan.recv_ready():
                outdata += chan.recv(1000)
            while chan.recv_stderr_ready():
                errdata += chan.recv_stderr(1000)
            if chan.exit_status_ready():
                break
        ssh_trans.close()
        ssh.close()
        retcode = chan.recv_exit_status()
        if retcode != 0:
            raise Exception("Error occurred while executing command")
        data = outdata.decode("utf-8").splitlines()
        for line in data:
            if line.startswith("#"):
                continue
            else:
                if "DenableOFTLS" in line:
                    if "true" in line:
                        status = "true"
                    else:
                        status = "false"
                    break
    except:
        messages.error(request, "Unable to connect remotely")
        return redirect("home")

    if status == "true":
        ipconfiglist.append({"ip": ip, "status": "enabled", "name": "TLS"})
    elif status == "false":
        ipconfiglist.append({"ip": ip, "status": "disabled", "name": "TLS"})

    newipconfiglist = []

    ###### Storing  only the most recent recent ip status#############
    for i in range(0, len(ipconfiglist)):

        for j in range(i, len(ipconfiglist)):

            if ipconfiglist[i]["ip"] == ipconfiglist[j]["ip"]:
                ipstatus = ipconfiglist[j]

        newipconfiglist.append(ipstatus)
    ###########################################################

    ####### Storing only unique values##################
    ipstatuslist = list()
    for i in newipconfiglist:
        if i not in ipstatuslist:
            ipstatuslist.append(i)
    #######################################################

    for i in ipstatuslist:
        with open("overallstatus.txt", "a") as file:
            file.write(i["ip"] + " " + i["status"] + " " + i["name"] + "\n")
    with open("username.txt") as file:
        username = file.read()

    sec_log_call(f"{username} viewed TLS configuration")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} viewed TLS configuration")

    with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
        if os.stat("onossec.log").st_size != 0:
            lastline = firstfile.readlines()[-1].strip()
            secondfile.write(lastline + "\n")
            syslog.syslog(syslog.LOG_INFO, lastline)

    return render(request, "sdntool/viewtls.html", {"ipconfiglist": ipstatuslist})