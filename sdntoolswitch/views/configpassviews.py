import json
import os
import re
import paramiko
import requests
import logging
from requests.auth import HTTPBasicAuth
from django.shortcuts import redirect, render
from django.contrib import messages
from django.views.decorators.cache import cache_control
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.role_validator import admin_manager_check
from sdntoolswitch.models import OnosServerManagement
from sdntoolswitch.utils import *
from sdntoolswitch.generic_logger import logger_call, create_logger

logger = create_logger(__package__.rsplit(".", 1)[-1], file_name="onossec.log")

@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addconfig(request):
    if request.method == "GET":
        return render(request, "sdntool/addconfig.html")
    onosusername = request.POST.get("onosuser")
    onospassword = request.POST.get("onospwd")
    onospasswordcnf = request.POST.get("onospwdcnf")
    sshuser = request.POST.get("sshuser")
    sshpass = request.POST.get("sshpass")
    sshport = request.POST.get("sshport")
    onoslocation = request.POST.get("fileloc")
    karaf = request.POST.get("karaf")
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
        "ssh_user": str(sshuser),
        "ssh_pass": str(sshpass),
        "ssh_port": int(sshport),
        "file_loc": str(onoslocation),
        "karaf_ver": str(karaf),
    }
    username = request.session["login"]["username"]
    onosServerRecords = OnosServerManagement.objects.values_list("iplist", flat=True)
    if len(onosServerRecords) != 0:
        onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
        try:
            dict(
                requests.get(
                    onosconfig["api_url"] + "devices",
                    auth=HTTPBasicAuth(onosconfig["onos_user"], onosconfig["onos_pwd"]),
                ).json()
            )
            if pwdcheck and not onosip in onosServerRecord.iplist.split(","):
                prevconfig = json.loads(onosServerRecord.multipleconfigjson)
                prevconfig.append(onosconfig)
                onosServerRecord.multipleconfigjson = json.dumps(prevconfig)
                onosServerRecord.iplist = onosServerRecord.iplist + "," + onosip
                onosServerRecord.save()
                return redirect("extraconfig")
            elif pwdcheck and onosServerRecord.iplist.split(",")[0] == onosip:
                messages.error(request, "Config already added for this ip address")
                return redirect("configcontroller")
            else:
                logger.warning("Password and confirmed passwords do not match")
                messages.error(request, "Password and confirmed passwords do not match")
                return redirect("configcontroller")
        except Exception as e:
            logger.warning(e.__str__())
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
                    iplist=onosip,
                    usercreated=username,
                    multipleconfigjson=json.dumps([onosconfig]),
                )
                onosServerRecord.save()
                return redirect("extraconfig")
            else:
                logger.warning("Password and confirmed passwords do not match")
                messages.error(request, "Password and confirmed passwords do not match")
                return redirect("configcontroller")
        except Exception as e:
            logger.warning(e.__str__())
            messages.error(
                request, "Wrong Input Credentials or ONOS not configured at this ip address"
            )
            return redirect("configcontroller")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addextraconfig(request):
    return render(request, "sdntool/extraconfig.html")

@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addconfigpassword(request):
    """
    View for adding password configuration
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []

    if request.method == "GET":
        return render(request, "sdntool/addconfigpassword.html", {"ip": iplist})
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
        return redirect("addconfigpasswordcontroller")

    status = request.POST.get("status")
    algorithm = request.POST.get("algo")
    host = str(ip)
    port = onosconfig["ssh_port"]
    sshuser = onosconfig["ssh_user"]
    password = onosconfig["ssh_pass"]
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
        karaf_ver = onosconfig["karaf_ver"]
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
        logger.warning("Unable to connect with given IP")
        messages.error(request, "Unable to connect with the given IP")
        return redirect("addconfigpasswordcontroller")
    msg = f"{username} configured password"
    logger.info(msg)
    logger_call(logging.INFO, msg, file_name="sds.log")
    messages.info(request, "ONOS Password Configured")
    return redirect("viewconfigurationpassword")

@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def modifypassword(request):
    """
    View for modifying password configuration
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []
    if request.method == "GET":
        return render(request, "sdntool/modifypassword.html", {"ip": iplist})
    status = request.POST.get("status")
    algorithm = request.POST.get("algo")
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
    except:
        logger.warning("No IP is given as input")
        messages.error(request, "No IP is given as input")
        return redirect("modifypassword")

    host = str(ip)
    port = onosconfig["ssh_port"]
    sshuser = onosconfig["ssh_user"]
    password = onosconfig["ssh_pass"]
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
        karaf_ver = onosconfig["karaf_ver"]
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
        logger.warning("Unable to connect with given IP")
        messages.error(request, "Unable to connect with given IP")
        return redirect("modifypassword")
    msg = f"{username} modified password configuration"
    logger.info(msg)
    logger_call(logging.INFO, msg, file_name="sds.log")
    messages.info(request, "ONOS Password configuration modified")
    return redirect("viewconfigurationpassword")

@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def disablepassword(request):
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []
    return render(request, "sdntool/disablepassword.html", {"ip": iplist})

@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def disablepasswordconfirm(request):
    """
    Controller for disabling password configuration
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []
    if request.method == "GET":
        return render(request, "sdntool/disablepassword.html", {"ip": iplist})
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
        return redirect("modifypassword")

    host = str(ip)
    port = onosconfig["ssh_port"]
    sshuser = onosconfig["ssh_user"]
    password = onosconfig["ssh_pass"]
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
        karaf_ver = onosconfig["karaf_ver"]
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
    msg = f"{username} disabled password configuration"
    logger_call(logging.INFO, msg, file_name="sds.log")
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
    configlist = json.loads(record.multipleconfigjson)

    for config in configlist:
        ip = config["ip"]
        host = str(ip)
        port = config["ssh_port"]
        username = config["ssh_user"]
        password = config["ssh_pass"]
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
        except Exception as e:
            logger.warning(f"Error occurred while connecting to the remote server {e.__str__()}")
            messages.error(request, "Error occurred while connecting to the remote server")
            return redirect("home")

        ipconfiglist.append({"ip": ip, "user": user, "password": password})
    newipconfiglist = []
    ########## Storing only recent status of ip ########
    for i in range(0, len(ipconfiglist)):
        for j in range(i, len(ipconfiglist)):
            if ipconfiglist[i]["ip"] == ipconfiglist[j]["ip"]:
                ipstatus = ipconfiglist[j]
        if ipstatus not in newipconfiglist:
            newipconfiglist.append(ipstatus)
    username = request.session["login"]["username"]
    msg = f"{username} viewed ONOS password Configuration"
    logger.info(msg)
    logger_call(logging.INFO, msg, file_name="sds.log")
    return render(
        request,
        "sdntool/viewpasswordconfiguration.html",
        {"ipconfiglist": newipconfiglist},
    )