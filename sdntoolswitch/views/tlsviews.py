import json
import os
import paramiko
import logging

from django.shortcuts import redirect, render
from django.contrib import messages
from django.views.decorators.cache import cache_control
from sdntoolswitch.models import OnosServerManagement
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.generic_logger import logger_call, create_logger

logger = create_logger(__package__.rsplit(".", 1)[-1], file_name="onossec.log")

ipconfiglist = []

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def modifytls(request):
    """
    View for modifying TLS
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []
    if request.method == "GET":
        return render(request, "sdntool/modifytls.html", {"ip": iplist})
    status = request.POST.get("status")
    keyloc = request.POST.get("keyloc")
    keypassword = request.POST.get("keypassword")
    trustloc = request.POST.get("trustloc")
    trustpassword = request.POST.get("trustpassword")
    ip = request.POST.get("ip")
    try:
        record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
        iplist = record.iplist.split(",")
        onosconfig = {}
        if ip in iplist:
            config = json.loads(record.multipleconfigjson)
            for i in config:
                if i["ip"] == ip:
                    onosconfig = i
                    break
        else:
            raise Exception
    except:
        logger.warning("No IP is given as input")
        messages.error(request, "No IP is given as input")
        return redirect("modifytls")

    host = str(ip)
    port = onosconfig["ssh_port"]
    sshuser = onosconfig["onos_user"]
    password = onosconfig["onos_pwd"]
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=sshuser, password=password)
    except:
        logger.warning("Unable to connect remotely")
        messages.error(request, "Unable to connect remotely")
        return redirect("home")
    # Create SFTP client
    sftp = ssh.open_sftp()
    try:
        onos_location = onosconfig["file_loc"]
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
        logger.warning("Unable to connect with given IP")
        messages.error(request, "Unable to connect with given IP")
        return redirect("modifytls")

    username = request.session["login"]["username"]

    logger_call(logging.INFO, f"{username} modified TLS", file_name="sds.log")
    logger.info(f"{username} modified TLS")

    messages.success(request, "Action Enabled")
    messages.info(request, "TLS configuration modified")
    return redirect("viewtls")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def disabletls(request):
    return render(request, "sdntool/disabletls.html")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def disabletlsconfirm(request):
    """
    Controller for disabling TLS
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []
    if request.method == "GET":
        return render(request, "sdntool/disabletlsip.html", {"ip": iplist})
    ip = request.POST.get("ip")

    try:
        record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
        iplist = record.iplist.split(",")
        onosconfig = {}
        if ip in iplist:
            config = json.loads(record.multipleconfigjson)
            for i in config:
                if i["ip"] == ip:
                    onosconfig = i
                    break
        else:
            raise Exception
    except:
        logger.warning("No IP is given as input")
        messages.error(request, "No IP is given as input")
        return redirect("disabletlsconfirm")

    host = str(ip)
    port = onosconfig["ssh_port"]
    sshuser = onosconfig["onos_user"]
    password = onosconfig["onos_pwd"]
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=sshuser, password=password)
    except:
        logger.warning("Unable to connect remotely")
        messages.error(request, "Unable to connect remotely")
        return redirect("home")
    # Create SFTP client
    sftp = ssh.open_sftp()
    try:
        onos_location = onosconfig["file_loc"]
        with sftp.open(f"{onos_location}/bin/onos-service", "r") as file:
            data = file.readlines()  ###### reading all lines

        data[10] = data[10].replace("true", "false")
        with sftp.open(f"{onos_location}/bin/onos-service", "w") as file:
            file.writelines(data)
        sftp.close()
        ssh.close()
    except:
        logger.warning("Unable to connect with given IP")
        messages.error(request, "Unable to connect with given IP")
        return redirect("disabletlsconfirm")

    messages.error(request, "TLS Disabled")
    messages.info(request, "TLS configured")
    username = request.session["login"]["username"]

    logger_call(logging.INFO, f"{username} disabled TLS", file_name="sds.log")
    logger.info(f"{username} disabled TLS")

    return redirect("viewtls")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def viewtls(request):
    """
    View for viewing TLS configuration
    """
    global ipconfiglist
    ipconfiglist = []
    record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
    configlist = json.loads(record.multipleconfigjson)
    for config in configlist:
        ip = config["ip"]
        host = str(ip)
        port = config["ssh_port"]
        username = config["ssh_user"]
        password = config["ssh_pass"]
        status = "false"
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
            logger.warning("Unable to connect remotely")
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
    username = request.session["login"]["username"]
    logger_call(logging.INFO, f"{username} viewed TLS configuration", file_name="sds.log")
    logger.info(f"{username} viewed TLS configuration")

    return render(request, "sdntool/viewtls.html", {"ipconfiglist": newipconfiglist})