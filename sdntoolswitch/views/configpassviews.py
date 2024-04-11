import json
import os
import re
import syslog
import paramiko
import requests
from requests.auth import HTTPBasicAuth
from django.shortcuts import redirect, render
from django.contrib import messages
from django.views.decorators.cache import cache_control
from sdntoolswitch.activitylogs import *
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.models import OnosServerManagement
from sdntoolswitch.onosseclogs import *
from sdntoolswitch.aaalogs import *
from sdntoolswitch.utils import *

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addconfig(request):
    if request.method == "GET":
        return render(request, "sdntool/addconfig.html")
    onosusername = request.POST.get("onosuser")
    onospassword = request.POST.get("onospwd")
    onospasswordcnf = request.POST.get("onospwdcnf")
    pwdcheck = checkonospwd(
        onospassword, onospasswordcnf
    )  ######## Checks the passwords and confirmed passwords given as input
    global onosip
    onosip = request.POST.get("onosip")
    onosport = request.POST.get("onosport")

    onosconfig = {
        "port_num": int(onosport),
        "onos_user": str(onosusername),
        "onos_pwd": str(onospassword),
        "api_url": "http://" + str(onosip) + ":" + str(onosport) + "/onos/v1/",
        "ip": str(onosip),
    }
    username = request.session["login"]["username"]
    onosServerRecords = OnosServerManagement.objects.values_list("primaryip", flat=True)
    if len(onosServerRecords) != 0:
        onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
        try:
            dict(
                requests.get(
                    onosconfig["api_url"] + "devices",
                    auth=HTTPBasicAuth(onosconfig["onos_user"], onosconfig["onos_pwd"]),
                ).json()
            )
            if pwdcheck and not onosServerRecord.primaryip == onosip:
                prevconfig = json.loads(onosServerRecord.multipleconfigjson)
                prevconfig.append(onosconfig)
                onosServerRecord.multipleconfigjson = json.dumps(prevconfig)
                onosServerRecord.save()
                return redirect("extraconfig")
            elif pwdcheck and onosServerRecord.primaryip == onosip:
                messages.error(request, "Config already added for this ip address")
                return redirect("configcontroller")
            else:
                messages.error(request, "Password and confirmed passwords do not match")
                return redirect("configcontroller")
        except Exception as e:
            print(e.__str__())
            messages.error(
                request, "Wrong Input Credentials or ONOS not configured at this ip address"
            )
            return redirect("configcontroller")
    else:
        try:
            dict(
                requests.get(
                    onosconfig["api_url"] + "devices",
                    auth=HTTPBasicAuth(onosconfig["onos_user"], onosconfig["onos_pwd"]),
                ).json()
            )
            if pwdcheck:
                onosServerRecord = OnosServerManagement.objects.create(
                    primaryip=onosip,
                    usercreated=username,
                    multipleconfigjson=json.dumps([onosconfig]),
                )
                onosServerRecord.save()
                return redirect("extraconfig")
            else:
                messages.error(request, "Password and confirmed passwords do not match")
                return redirect("configcontroller")
        except Exception as e:
            print(e.__str__())
            messages.error(
                request, "Wrong Input Credentials or ONOS not configured at this ip address"
            )
            return redirect("configcontroller")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addextraconfig(request):
    return render(request, "sdntool/extraconfig.html")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addconfigpassword(request):
    """
    View for adding password configuration
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = [config["ip"] for config in json.loads(onosServerRecord.multipleconfigjson)]
    except:
        iplist = []

    if request.method == "GET":
        return render(request, "sdntool/addconfigpassword.html", {"ip": iplist})
    ip = request.POST.get("ip")

    try:
        record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
        primaryip = str(record.primaryip)
        if primaryip == ip:
            pass
        else:
            raise Exception
    except:
        messages.error(request, "No IP is given as input")
        return redirect("addconfigpasswordcontroller")

    status = request.POST.get("status")
    algorithm = request.POST.get("algo")
    host = str(ip)
    port = 22
    sshuser = request.POST.get("sshuser")
    password = request.POST.get("sshpass")
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=sshuser, password=password)
    except:
        messages.error(request, "Unable to connect remotely")
        return redirect("home")
    # Create SFTP client
    sftp = ssh.open_sftp()

    try:
        onos_location = request.POST.get("fileloc")
        karaf_ver = request.POST.get("karaf")
        with sftp.open(
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.apache.karaf.jaas.cfg",
            "r",
        ) as file:
            data = file.readlines()  ###### reading file lines

        for i in range(len(data)):
            if data[i].startswith("encryption.algorithm"):
                data[i] = "encryption.algorithm =" + str(algorithm) + "\n"
            elif data[i].startswith("encryption.enabled"):
                if status == "true":
                    data[i] = "encryption.enabled = true\n"
                    messages.success(request, "Action enabled")
                else:
                    data[i] = "encryption.enabled = false\n"
                    messages.error(request, "Action disabled")

        with sftp.open(
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.apache.karaf.jaas.cfg",
            "w",
        ) as file:
            file.writelines(data)
        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to connect with the given IP")
        return redirect("addconfigpasswordcontroller")

    sec_log_call(f"{username} configured password")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} configured password")
    with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
        if os.stat("onossec.log").st_size != 0:
            lastline = firstfile.readlines()[-1].strip()
            secondfile.write(lastline + "\n")
            syslog.syslog(syslog.LOG_INFO, lastline)
    messages.info(request, "ONOS Password Configured")
    return redirect("viewconfigurationpassword")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def modifypassword(request):
    """
    View for modifying password configuration
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = [config["ip"] for config in json.loads(onosServerRecord.multipleconfigjson)]
    except:
        iplist = []
    if request.method == "GET":
        return render(request, "sdntool/modifypassword.html", {"ip": iplist})
    status = request.POST.get("status")
    algorithm = request.POST.get("algo")
    ip = request.POST.get("ip")

    try:
        record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
        primaryip = str(record.primaryip)
        if primaryip == ip:
            pass
        else:
            raise Exception
    except:
        messages.error(request, "No IP is given as input")
        return redirect("modifypassword")

    host = str(ip)
    port = 22
    sshuser = request.POST.get("sshuser")
    password = request.POST.get("sshpass")
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=sshuser, password=password)
    except:
        messages.error(request, "Unable to connect remotely")
        return redirect("home")
    # Create SFTP client
    sftp = ssh.open_sftp()
    try:
        onos_location = request.POST.get("fileloc")
        karaf_ver = request.POST.get("karaf")
        with sftp.open(
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.apache.karaf.jaas.cfg",
            "r",
        ) as file:
            data = file.readlines()  ######reading file lines

        for i in range(len(data)):
            if data[i].startswith("encryption.algorithm"):
                data[i] = "encryption.algorithm =" + str(algorithm) + "\n"
            elif data[i].startswith("encryption.enabled"):
                if status == "true":
                    data[i] = "encryption.enabled = true\n"
                    messages.success(request, "Action enabled")
                else:
                    data[i] = "encryption.enabled = false\n"
                    messages.error(request, "Action disabled")

        with sftp.open(
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.apache.karaf.jaas.cfg",
            "w",
        ) as file:
            file.writelines(data)

        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to connect with given IP")
        return redirect("modifypassword")

    sec_log_call(f"{username} modified password configuration")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} modified password configuration")
    with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
        if os.stat("onossec.log").st_size != 0:
            lastline = firstfile.readlines()[-1].strip()
            secondfile.write(lastline + "\n")
            syslog.syslog(syslog.LOG_INFO, lastline)
    messages.info(request, "ONOS Password configuration modified")
    return redirect("viewconfigurationpassword")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def disablepassword(request):
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = [config["ip"] for config in json.loads(onosServerRecord.multipleconfigjson)]
    except:
        iplist = []
    return render(request, "sdntool/disablepassword.html", {"ip": iplist})

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def disablepasswordconfirm(request):
    """
    Controller for disabling password configuration
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = [config["ip"] for config in json.loads(onosServerRecord.multipleconfigjson)]
    except:
        iplist = []
    if request.method == "GET":
        return render(request, "sdntool/disablepassword.html", {"ip": iplist})
    ip = request.POST.get("ip")

    try:
        record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
        primaryip = str(record.primaryip)
        if primaryip == ip:
            pass
        else:
            raise Exception
    except:
        messages.error(request, "No IP is given as input")
        return redirect("modifypassword")

    host = str(ip)
    port = 22
    sshuser = request.POST.get("sshuser")
    password = request.POST.get("sshpass")
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=sshuser, password=password)
    except:
        messages.error(request, "Unable to connect remotely")
        return redirect("home")
    # Create SFTP client
    sftp = ssh.open_sftp()
    try:
        onos_location = request.POST.get("fileloc")
        karaf_ver = request.POST.get("karaf")
        with sftp.open(
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.apache.karaf.jaas.cfg",
            "r",
        ) as file:
            data = file.read()  ######reading file lines

        re.sub("encryption.enabled = true", "encryption.enabled = false", data)
        with sftp.open(
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.apache.karaf.jaas.cfg",
            "w",
        ) as file:
            file.write(data)

        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to connect with given IP")
        return redirect("modifypassword")
    messages.error(request, "Password encryption disabled")
    log_call(f"{username} disabled ONOS password configuration")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} disabled ONOS password configuration")

    return redirect("viewconfigurationpassword")


ipconfiglist = list()

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def viewpasswordconfiguration(request):
    """
    View for viewing password configuration
    """

    global ipconfiglist
    record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
    ip = str(record.primaryip)

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
        chan.exec_command("cat etc/users.properties")
        while True:
            while chan.recv_ready():
                outdata += chan.recv(1000)
            while chan.recv_stderr_ready():
                errdata += chan.recv_stderr(1000)
            if chan.exit_status_ready():
                break
        ssh_trans.close()
        retcode = chan.recv_exit_status()
        ssh.close()
        if retcode != 0:
            raise Exception("Error occurred while executing command")
        data = outdata.decode("utf-8").splitlines()
        pattern = re.compile(r"(\w+)\s+=\s+(\w+),_g_:(\w+)")
        for line in data:
            match = pattern.match(line)
            if match:
                user = match.group(1)
                password = match.group(2)
                break
    except:
        messages.error(request, "Error occurred while connecting to the remote server")
        return redirect("home")

    ipconfiglist.append({"ip": ip, "user": user, "password": password})
    newipconfiglist = []
    ########## Storing only recent status of ip ########
    for i in range(0, len(ipconfiglist)):
        for j in range(i, len(ipconfiglist)):
            if ipconfiglist[i]["ip"] == ipconfiglist[j]["ip"]:
                ipstatus = ipconfiglist[j]

        newipconfiglist.append(ipstatus)
    #####################################################

    ######## Storing only unique values###########
    ipstatuslist = list()
    for i in newipconfiglist:
        if i not in ipstatuslist:
            ipstatuslist.append(i)
    username = request.session["login"]["username"]

    sec_log_call(f"{username} viewed ONOS password Configuration")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} viewed ONOS password Configuration")
    with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
        if os.stat("onossec.log").st_size != 0:
            lastline = firstfile.readlines()[-1].strip()
            secondfile.write(lastline + "\n")
            syslog.syslog(syslog.LOG_INFO, lastline)
    return render(
        request,
        "sdntool/viewpasswordconfiguration.html",
        {"ipconfiglist": ipstatuslist},
    )