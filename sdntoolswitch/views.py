import json
import syslog
import time

from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.views.decorators.cache import cache_control
from sdntoolswitch.models import Usermanagement
from sdntoolswitch.formvalidation import Validator
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.activitylogs import *
from sdntoolswitch.onosseclogs import *
from sdntoolswitch.aaalogs import *
from datetime import datetime
import re
import requests
from requests.auth import HTTPBasicAuth
from .utils import *
import paramiko
import os

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

def login(request):
    """
    View for login page
    """
    return render(request, "sdntool/index.html")


def logincontroller(request):
    """
    Controller for login page
    """
    global username
    global password
    username = request.POST.get("username")
    password = request.POST.get("password")
    with open("username.txt", "w") as file:
        file.write(username)

    validator = Validator(
        {
            "username": "required|string",
            "password": "required|string",
        }
    )
    validator.run_validation(request.POST.dict())
    if not validator.valid:
        validator.error_message(request)
        return redirect("login")
    else:
        try:
            user = Usermanagement.objects.get(username=username)
        except Usermanagement.DoesNotExist:
            user = None
        if user is not None:
            if check_password(password, user.password):
                request.session["login"] = {
                    "username": user.username,
                    "loginc": True,
                    "userrole": user.userrole,
                }
                if request.session["login"]["username"] != "operator":
                    return redirect("configcontroller")
                else:
                    return redirect("home")

            else:
                messages.error(
                    request, "Your password is not correct", extra_tags="loginerror"
                )
                return redirect("login")
        else:
            messages.error(request, "User does not exists", extra_tags="loginerror")
            return redirect("login")


def logout(request):
    """
    Controller for logout
    """
    global username
    del request.session["login"]
    with open("iplist.txt", "w") as file:
        file.truncate()
    with open("portconf.json", "w") as file:
        file.truncate()
    with open("username.txt") as file:
        username = file.read()
    log_call(f"{username} logged out")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} logged out")
    return redirect("login")


@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def home(request):
    """
    View for home page
    """
    data = {
        "title": "Dashboard",
    }
    with open("iplist.txt", "r") as file:
        ip = file.readlines()

    with open("username.txt") as file:
        username = file.read()
    log_call(f"{username} logged in")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} logged in")
    return render(request, "sdntool/home.html", {"ip": ip})


def aaa(request):
    with open("iplist.txt", "r") as file:
        iplist = file.readlines()

    if request.method == "GET":
        return render(request, "sdntool/aaaip.html", {"ip": iplist})

    ip = request.POST.get("ip")

    try:
        with open("userip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP is given as input")
        return redirect("home")

    return render(request, "sdntool/configureradius.html", {"ip": ip})


##### This method used as controller of AAA form data ##############
def aaacontroller(request):
    radiusip = request.POST.get("radiusip")
    radiusport = request.POST.get("radiusport")
    radiussecret = request.POST.get("radiussecret")
    ip = request.POST.get("ip")
    ipregex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if not re.search(ipregex, str(radiusip)):
        messages.error(request, "Not a valid Ip address")
        return render(request, "sdntool/configureradius.html")
    if not re.search("^[0-9]*$", radiusport):
        messages.error(request, "Not a valid port")
        return render(request, "sdntool/configureradius.html")

    host = str(ip)
    port = 22
    username = "neha"
    password = "cdcju"
    # # Establish SSH connection
    ssh = paramiko.SSHClient()

    # client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)
    except:
        messages.error(request, "Unable to connect")
        return render(request, "sdntool/configureradius.html")

    # Create SFTP client
    sftp = ssh.open_sftp()
    aaaconfig = {
        "apps": {
            "org.opencord.aaa": {
                "AAA": {
                    "radiusIp": str(radiusip),
                    "radiusServerPort": str(radiusport),
                    "radiusSecret": str(radiussecret),
                }
            }
        }
    }
    aaaconfigjson = json.dumps(aaaconfig)

    with sftp.open("/home/neha/onos/aaa-conf.json", "w") as file:
        file.write(aaaconfigjson)
    try:
        # Execute a command on the remote server

        ssh.exec_command(
            "./onos/tools/package/runtime/bin/onos-netcfg localhost /home/neha/onos/aaa-conf.json"
        )

        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to execute command")
        return redirect("home")
    with open("username.txt") as file:
        username = file.read()

    aaalog_call(f"{username} configured AAA")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} configured AAA")
    messages.info(request, "AAA configured")
    return redirect("viewradius")


###### This method used for viewing radius configuration#########3
def viewradius(request):
    with open("userip.txt", "r") as file:
        ip = file.read()
    host = str(ip)
    port = 22
    username = "neha"
    password = "cdcju"
    # # Establish SSH connection
    ssh = paramiko.SSHClient()

    # client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)
    except:
        messages.error(request, "Unable to connect")
        return redirect("home")

    # Create SFTP client
    sftp = ssh.open_sftp()

    with sftp.open("/home/neha/onos/aaa-conf.json", "r") as config_file:
        data = config_file.read()
    config = json.loads(data)  ####### reading the json file

    radiusip = config["apps"]["org.opencord.aaa"]["AAA"]["radiusIp"]
    with open("username.txt") as file:
        username = file.read()
    aaalog_call(f"{username} viewed AAA")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} viewed AAA")
    return render(request, "sdntool/viewradius.html", {"radius": radiusip})


def createuserform(request):
    """
    View for creating user form
    """
    global username
    return render(request, "sdntool/Createuser.html")


@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def Createuser(request):
    """
    Controller for creating user
    """
    global username
    user = request.POST.get("U_id")
    password = make_password(request.POST.get("P_id"))
    type = request.POST.get("type")
    userdata = Usermanagement.objects.create(
        username=user, password=password, userrole=type
    )
    userdata.save()
    with open("username.txt") as file:
        username = file.read()

    log_call(f"{username} created new {type} user {user}")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} created new {type} user {user}")
    return redirect("showusers")


def deleteuser(request, id):
    """
    Controller for deleting user
    """
    global username
    userdata = Usermanagement.objects.get(idusermanagement=id)
    userdata.status = "INACTIVE"
    userdata.save()
    with open("username.txt") as file:
        username = file.read()

    log_call(f"{username} deleted {userdata.userrole} user {userdata.username}")
    syslog.syslog(
        syslog.LOG_DEBUG,
        f"{username} deleted {userdata.userrole} user {userdata.username}",
    )

    return redirect("showusers")


def users(request):
    """
    View for users
    """
    global username
    userdata = Usermanagement.objects.filter(status="ACTIVE")
    with open("username.txt") as file:
        username = file.read()

    log_call(f"{username} monitored user details")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} monitored user details")
    return render(request, "sdntool/showusers.html", {"userdata": userdata})


def log(request):
    """
    View for SDS logs
    """
    if request.method == "POST":
        loglist = list()
        start = request.POST.get("startdate")
        start = datetime.strptime(start, "%Y-%m-%d").date()

        end = request.POST.get("enddate")
        end = datetime.strptime(end, "%Y-%m-%d").date()
        if start > end:
            messages.error(request, "start date should be less than end date")
            return redirect("date")

        with open("sds.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)

                # computed date
                # feeding format
                dt = datetime.strptime(match_str.group(), "%Y-%m-%d").date()

                f = file.split(" - ")
                if dt >= start and dt <= end:

                    loglist.append(
                        {
                            "status": f[-1],
                            "datetime": f[-3],
                            "date": str(dt),
                            "app": f[-4],
                        }
                    )
        loglist.reverse()
    else:

        loglist = list()
        with open("sds.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)

                f = file.split(" - ")

                loglist.append({"status": f[-1], "datetime": f[-3], "app": f[-4]})
        loglist.reverse()

    return render(request, "sdntool/log.html", {"logresponse": loglist})


def onosseclog(request):
    """
    View for ONOS security logs
    """
    if request.method == "POST":
        loglist = list()
        start = request.POST.get("startdate")
        start = datetime.strptime(start, "%Y-%m-%d").date()

        end = request.POST.get("enddate")
        end = datetime.strptime(end, "%Y-%m-%d").date()
        if start > end:
            messages.error(request, "start date should be less than end date")
            return redirect("date")

        with open("onossec.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)

                # computed date
                # feeding format
                dt = datetime.strptime(match_str.group(), "%Y-%m-%d").date()

                f = file.split(" - ")
                if dt >= start and dt <= end:

                    loglist.append(
                        {
                            "status": f[-1],
                            "datetime": f[-3],
                            "date": str(dt),
                            "app": f[-4],
                        }
                    )
        loglist.reverse()
    else:

        loglist = list()
        with open("onossec.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)

                f = file.split(" - ")

                loglist.append({"status": f[-1], "datetime": f[-3], "app": f[-4]})
        loglist.reverse()

    return render(request, "sdntool/onosseclog.html", {"logresponse": loglist})


def aaalog(request):
    """
    View for AAA logs
    """
    if request.method == "POST":
        loglist = list()
        start = request.POST.get("startdate")
        start = datetime.strptime(start, "%Y-%m-%d").date()

        end = request.POST.get("enddate")
        end = datetime.strptime(end, "%Y-%m-%d").date()
        if start > end:
            messages.error(request, "start date should be less than end date")
            return redirect("date")

        with open("aaa.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)
                dt = datetime.strptime(match_str.group(), "%Y-%m-%d").date()

                f = file.split(" - ")
                if dt >= start and dt <= end:

                    loglist.append(
                        {
                            "status": f[-1],
                            "datetime": f[-3],
                            "date": str(dt),
                            "app": f[-4],
                        }
                    )
        loglist.reverse()
    else:

        loglist = list()
        with open("aaa.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)

                f = file.split(" - ")

                loglist.append({"status": f[-1], "datetime": f[-3], "app": f[-4]})
        loglist.reverse()

    return render(request, "sdntool/aaalogs.html", {"logresponse": loglist})


######## This method used for rendering date form for AAA ##########
def aaadateform(request):
    return render(request, "sdntool/aaadate.html")


def deleteaaalogconfirm(request):
    return render(request, "sdntool/deleteaaalogs.html")


########## This method used for deleting AAA logs###########
def deleteaaalogs(request):

    with open("aaa.log", "w") as logfile:
        logfile.truncate()
    return redirect("aaalog")


######## This method used for rendering date form for ONOS security logs ##########
def onossecdateform(request):
    return render(request, "sdntool/onossecdate.html")


######## This method used for rendering date form for SDS logs ##########
def dateform(request):
    return render(request, "sdntool/date.html")


def deleteonosseclogconfirm(request):
    return render(request, "sdntool/deleteonosseclogs.html")


######## This method used for deleting ONOS security logs ##########
def deleteonosseclogs(request):
    with open("onossec.log", "w") as logfile:
        logfile.truncate()
    return redirect("onosseclog")


######## This method used for deleting logs for SDS ##########
def deletelogs(request):

    with open("sds.log", "w") as logfile:
        logfile.truncate()
    return redirect("logmanagement")


def deletelogconfirm(request):
    return render(request, "sdntool/deletelogs.html")


def securitystats(request):
    return render(request, "sdntool/securitystats.html")


############ This method used for adding ONOS configuration###########

onosiplist = list()


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
        "port_num": str(onosport),
        "onos_user": str(onosusername),
        "onos_pwd": str(onospassword),
        "api_url": "http://" + str(onosip) + ":" + str(onosport) + "/onos/v1/",
        "ip": str(onosip),
    }
    onosconfigjson = json.dumps(onosconfig)  ########## converts dictionary to json
    with open("config.json", "w") as outfile:
        outfile.write(onosconfigjson)  ###### writing json to file
    outfile.close()
    with open("config.json") as config_file:
        data = config_file.read()
    config = json.loads(data)  ####### reading the json file

    global port_num
    global onos_username
    global onos_password
    global onos_api
    global onos_ip

    port_num = config["port_num"]
    onos_username = config["onos_user"]
    onos_password = config["onos_pwd"]
    onos_api = config["api_url"]
    onos_ip = config["ip"]
    ######### checking if ONOS configured at the input Ip address##########
    try:
        dict(
            requests.get(
                onos_api + "devices",
                auth=HTTPBasicAuth(onos_username, onos_password),
            ).json()
        )
    except:
        messages.error(
            request, "Wrong Input Credentials or ONOS not configured at this ip address"
        )
        return redirect("configcontroller")
    ###############################################################################
    if pwdcheck:  #### if password and confirmed passwords match
        with open("ipbackup.txt", "w") as file:
            pass
        with open("iplist.txt", "a") as file:
            file.write(onosip + "\n")
        return redirect("extraconfig")

    else:
        messages.error(request, "Password and confirmed passwords do not match")
        return redirect("configcontroller")


with open("config.json") as config_file:
    data = config_file.read()
config = json.loads(data)  ####### reading the json file


global port_num
global onos_username
global onos_password
global onos_api
global onos_ip


port_num = config["port_num"]
onos_username = config["onos_user"]
onos_password = config["onos_pwd"]
onos_api = config["api_url"]
onos_ip = config["ip"]


######## This method used for asking for extra ONOS configurations##########
def addextraconfig(request):
    return render(request, "sdntool/extraconfig.html")


######### This method used for adding ONOS password configuration###########
def addconfigpassword(request):

    with open("iplist.txt", "r") as file:
        iplist = file.readlines()

    if request.method == "GET":
        return render(request, "sdntool/addconfigpassword.html", {"ip": iplist})

    ip = request.POST.get("ip")

    try:
        with open("userip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP is given as input")
        return redirect("addconfigpasswordcontroller")

    status = request.POST.get("status")
    algorithm = request.POST.get("algo")
    host = str(ip)
    port = 22
    username = "sdn"
    password = "cdcju"
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

        with sftp.open(
            "/home/sdn/Documents/onos/apache-karaf-4.2.9/etc/org.apache.karaf.jaas.cfg",
            "r",
        ) as file:
            data = file.readlines()  ###### reading file lines

        if status == "true":
            data[23] = "encryption.enabled = true\n"

            data[53] = "encryption.algorithm =" + str(algorithm) + "\n"
            messages.success(request, "Action enabled")
        else:
            data[23] = "encryption.enabled = false\n"

            data[53] = "encryption.algorithm =" + str(algorithm) + "\n"
            messages.error(request, "Action disabled")

        with sftp.open(
            "/home/sdn/Documents/onos/apache-karaf-4.2.9/etc/org.apache.karaf.jaas.cfg",
            "w",
        ) as file:
            file.writelines(data)
        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to connect with the given IP")
        return redirect("addconfigpasswordcontroller")
    with open("username.txt") as file:
        username = file.read()

    sec_log_call(f"{username} configured password")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} configured password")
    with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
        if os.stat("onossec.log").st_size != 0:
            lastline = firstfile.readlines()[-1].strip()
            secondfile.write(lastline + "\n")
            syslog.syslog(syslog.LOG_INFO, lastline)
    messages.info(request, "ONOS Password Configured")
    return redirect("viewconfigurationpassword")


######### This method used for modifying password##############3
def modifypassword(request):
    with open("iplist.txt", "r") as file:
        iplist = file.readlines()
    if request.method == "GET":
        return render(request, "sdntool/modifypassword.html", {"ip": iplist})
    status = request.POST.get("status")
    algorithm = request.POST.get("algo")
    ip = request.POST.get("ip")

    try:
        with open("userip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP is given as input")
        return redirect("modifypassword")

    host = str(ip)
    port = 22
    username = "sdn"
    password = "cdcju"
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

        with sftp.open(
            "/home/sdn/Documents/onos/apache-karaf-4.2.9/etc/org.apache.karaf.jaas.cfg",
            "r",
        ) as file:
            data = file.readlines()  ######reading file lines

        if status == "true":
            data[23] = "encryption.enabled = true\n"

            data[53] = "encryption.algorithm =" + str(algorithm) + "\n"
            messages.success(request, "Action Enabled")
        else:
            data[23] = "encryption.enabled = false\n"

            data[53] = "encryption.algorithm =" + str(algorithm) + "\n"
            messages.error(request, "Action disabled")

        with sftp.open(
            "/home/sdn/Documents/onos/apache-karaf-4.2.9/etc/org.apache.karaf.jaas.cfg",
            "w",
        ) as file:
            file.writelines(data)

        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to connect with given IP")
        return redirect("modifypassword")
    with open("username.txt") as file:
        username = file.read()

    sec_log_call(f"{username} modified password configuration")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} modified password configuration")
    with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
        if os.stat("onossec.log").st_size != 0:
            lastline = firstfile.readlines()[-1].strip()
            secondfile.write(lastline + "\n")
            syslog.syslog(syslog.LOG_INFO, lastline)
    messages.info(request, "ONOS Password configuration modified")
    return redirect("viewconfigurationpassword")


def disablepassword(request):

    return render(request, "sdntool/disablepassword.html")


######### This method used for disabling password############
def disablepasswordconfirm(request):
    with open(
        "/home/sdn/Documents/onos/apache-karaf-4.2.9/etc/org.apache.karaf.jaas.cfg", "r"
    ) as file:
        data = file.readlines()  ###### reading file lines
    data[23] = data[23].replace("true", "false")

    with open(
        "/home/sdn/Documents/onos/apache-karaf-4.2.9/etc/org.apache.karaf.jaas.cfg", "w"
    ) as file:
        file.writelines(data)
    messages.error(request, "Password encryption disabled")
    with open("username.txt") as file:
        username = file.read()
    log_call(f"{username} disabled ONOS password configuration")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} disabled ONOS password configuration")

    return redirect("viewconfigurationpassword")


ipconfiglist = list()


####### This method used for viewing password configuration#########
def viewpasswordconfiguration(request):

    global ipconfiglist
    with open("userip.txt", "r") as file:
        ip = file.read()

    host = str(ip)
    port = 22
    username = "sdn"
    password = "cdcju"
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)
    except:
        messages.error(request, "No IP is given as input")
        return redirect("home")

    # Create SFTP client
    sftp = ssh.open_sftp()
    try:

        with sftp.open(
            "/home/sdn/Documents/onos/apache-karaf-4.2.9/etc/users.properties"
        ) as file:
            data = file.readlines()
        data[31] = data[31][:100]

        data[31] = data[31].split("=")
        user = data[31][0]
        password = data[31][1].split(",")[0]

        # Close the SFTP session and SSH connection
        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to connect with given IP")
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
    with open("username.txt") as file:
        username = file.read()

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


######### This method used for configuring HTTPS#############


def confighttp(request):
    with open("iplist.txt", "r") as file:
        iplist = file.readlines()
    if request.method == "GET":
        return render(request, "sdntool/confighttp.html", {"ip": iplist})
    status = request.POST.get("status")
    keyloc = request.POST.get("key")
    httppassword = request.POST.get("password")
    cnfpassword = request.POST.get("cnfpassword")
    ip = request.POST.get("ip")
    try:
        with open("userip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP is given as input")
        return redirect("confighttp")

    host = str(ip)
    port = 22
    username = "srijita"
    password = "cdcju"
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

        with sftp.open(
            "/home/srijita/Videos/onos-2.5.1/apache-karaf-4.2.9/etc/org.ops4j.pax.web.cfg",
            "r",
        ) as file:
            data = file.readlines()  ###### reading all lines

        if status == "true":
            data[4] = 'org.osgi.service.http.secure.enabled="+true+"\n'
            data[6] = "org.ops4j.pax.web.ssl.keystore=" + keyloc + "\n"
            data[7] = "org.ops4j.pax.web.ssl.password=" + httppassword + "\n"
            data[8] = "org.ops4j.pax.web.ssl.keypassword=" + cnfpassword + "\n"
            messages.success(request, "Action Enabled")
        else:
            data[4] = "org.osgi.service.http.secure.enabled=false\n"
            data[6] = "org.ops4j.pax.web.ssl.keystore=" + keyloc + "\n"
            data[7] = "org.ops4j.pax.web.ssl.password=" + httppassword + "\n"
            data[8] = "org.ops4j.pax.web.ssl.keypassword=" + cnfpassword + "\n"
            messages.error(request, "Action Disabled")

        with open(
            "/home/srijita/Videos/onos-2.5.1/apache-karaf-4.2.9/etc/org.ops4j.pax.web.cfg",
            "w",
        ) as file:
            file.writelines(data)

        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to connect with given IP")
        return redirect("confighttp")

    messages.info(request, "HTTPS Authentication Configured")

    if httppassword == cnfpassword:
        with open("username.txt") as file:
            username = file.read()

        sec_log_call(f"{username} configured HTTPS")
        syslog.syslog(syslog.LOG_DEBUG, f"{username} configured HTTPS")

        with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
            if os.stat("onossec.log").st_size != 0:
                lastline = firstfile.readlines()[-1].strip()
                secondfile.write(lastline + "\n")
                syslog.syslog(syslog.LOG_INFO, lastline)
        return redirect("viewhttp")
    else:
        messages.error(request, "Password and confirmed passwords do not match")
        return redirect("confighttp")


######### This method used for modifying HTTPS configuration##############
def modifyhttp(request):
    with open("iplist.txt", "r") as file:
        iplist = file.readlines()
    if request.method == "GET":
        return render(request, "sdntool/modifyhttp.html", {"ip": iplist})
    status = request.POST.get("status")
    keyloc = request.POST.get("key")
    httppassword = request.POST.get("password")
    cnfpassword = request.POST.get("cnfpassword")
    ip = request.POST.get("ip")
    username = request.POST.get("sshuser")
    password = request.POST.get("sshpass")
    fileloc = request.POST.get("fileloc")
    try:
        with open("userip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP is given as input")
        return redirect("modifyhttp")

    host = str(ip)
    port = 22
    # username = 'srijita'
    # password = 'cdcju'
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)

    except paramiko.AuthenticationException:
        # print("Authentication failed, please verify your credentials: %s")
        messages.error(
            request,
            "Authentication failed, please verify your credentials: %s"
            % paramiko.AuthenticationException,
        )
        return redirect("home")
    except paramiko.BadHostKeyException as badHostKeyException:
        messages.error(
            request, "Unable to verify server's host key: %s" % badHostKeyException
        )
        return redirect("home")

    except paramiko.SSHException as sshException:
        # print("Unable to establish SSH connection: %s" % sshException)
        messages.error(request, "Unable to establish SSH connection: %s" % sshException)
        return redirect("home")

    # Create SFTP client
    sftp = ssh.open_sftp()
    try:
        datatowrite = """
                org.osgi.service.http.port=8181
                org.osgi.service.http.port.secure=8443

                org.osgi.service.http.enabled=true
                org.osgi.service.http.secure.enabled=true

                org.ops4j.pax.web.ssl.keystore={}
                org.ops4j.pax.web.ssl.password={}
                org.ops4j.pax.web.ssl.keypassword={}


                org.ops4j.pax.web.session.timeout=1440

                org.ops4j.pax.web.session.url=none
                org.ops4j.pax.web.config.file=./etc/jetty.xml
                """.format(
            keyloc, httppassword, cnfpassword
        )

        # print(datatowrite)
        with sftp.open(fileloc, "w") as f:
            f.writelines(datatowrite)
        sftp.close()
        ssh.close()
    except Exception as e:
        print(e)
        messages.error(request, "Unable to connect with given IP")
        return redirect("modifyhttp")

    if httppassword == cnfpassword:
        with open("username.txt") as file:
            username = file.read()

        sec_log_call(f"{username} modified HTTPS")

        syslog.syslog(syslog.LOG_DEBUG, f"{username} modified HTTPS")

        with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
            if os.stat("onossec.log").st_size != 0:

                lastline = firstfile.readlines()[-1].strip()
                secondfile.write(lastline + "\n")
                syslog.syslog(syslog.LOG_INFO, lastline)

        messages.info(request, "HTTPS configuration modified")
        return redirect("viewhttp")
    else:
        messages.error(request, "Password and confirmed passwords do not match")
        return redirect("modifyhttp")


def disablehttp(request):
    if request.method == "GET":
        return render(request, "sdntool/disablehttp.html")


######### This method used for disabling HTTPS###################
def disablehttpconfirm(request):
    with open("iplist.txt", "r") as file:
        iplist = file.readlines()
    if request.method == "GET":
        return render(request, "sdntool/disablehttpip.html", {"ip": iplist})
    ip = request.POST.get("ip")

    try:
        with open("userip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP is given as input")
        return redirect("httpdisableconfirm")

    host = str(ip)
    port = 22
    username = "srijita"
    password = "cdcju"
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

        datatowrite = """
org.osgi.service.http.port=8181
org.osgi.service.http.port.secure=8443

org.osgi.service.http.enabled=true
org.osgi.service.http.secure.enabled=false

org.ops4j.pax.web.ssl.keystore=etc/keystore
org.ops4j.pax.web.ssl.password=222222
org.ops4j.pax.web.ssl.keypassword=222222


org.ops4j.pax.web.session.timeout=1440

org.ops4j.pax.web.session.url=none
org.ops4j.pax.web.config.file=./etc/jetty.xml
"""

        with sftp.open(
            "/home/srijita/Videos/onos-2.5.1/apache-karaf-4.2.9/etc/org.ops4j.pax.web.cfg",
            "r",
        ) as file:
            data = file.readlines()  ###### reading all lines
        data[4] = "org.osgi.service.http.secure.enabled=false\n"

        with sftp.open(
            "/home/srijita/Videos/onos-2.5.1/apache-karaf-4.2.9/etc/org.ops4j.pax.web.cfg",
            "w",
        ) as file:
            file.writelines(datatowrite)
        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to connect with given IP")
        return redirect("httpdisableconfirm")
    with open("username.txt") as file:
        username = file.read()

    sec_log_call(f"{username} disabled HTTPS")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} disabled HTTPS")

    with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
        if os.stat("onossec.log").st_size != 0:
            lastline = firstfile.readlines()[-1].strip()
            secondfile.write(lastline + "\n")
            syslog.syslog(syslog.LOG_INFO, lastline)
    messages.error(request, "HTTPS disabled")
    return redirect("viewhttp")


ipconfiglist = list()


######### This method used for viewing HTTPS configuration###############
def viewhttp(request):
    global ipconfiglist

    with open("userip.txt", "r") as file:
        ip = file.read()

    host = str(ip)
    port = 22
    username = "srijita"
    password = "cdcju"
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)
    except:
        messages.error(request, "No IP is given as input")
        return redirect(home)

    # Create SFTP client
    sftp = ssh.open_sftp()
    try:

        with sftp.open(
            "/home/srijita/Videos/onos-2.5.1/onos/apache-karaf-4.2.9/etc/org.ops4j.pax.web.cfg",
            "r",
        ) as file:
            data = file.readlines()  ###### reading all lines
    except:
        messages.error(request, "Unable to connect with given IP")
        return redirect("home")

    status = data[4].split("=")[1]

    sftp.close()
    ssh.close()
    if status == "true\n":
        ipconfiglist.append({"ip": ip, "status": "enabled", "name": "HTTPS"})
    else:
        ipconfiglist.append({"ip": ip, "status": "disabled", "name": "HTTPS"})
    newipconfiglist = []

    ######### Storing only the most recent ip status################
    for i in range(0, len(ipconfiglist)):
        for j in range(i, len(ipconfiglist)):
            if ipconfiglist[i]["ip"] == ipconfiglist[j]["ip"]:
                ipstatus = ipconfiglist[j]

        newipconfiglist.append(ipstatus)
    ###########################################################

    ######### Storing only unique values#############################
    ipstatuslist = list()
    for i in newipconfiglist:
        if i not in ipstatuslist:
            ipstatuslist.append(i)

    for i in ipstatuslist:
        with open("overallstatus.txt", "a") as file:
            file.write(i["ip"] + " " + i["status"] + " " + i["name"] + "\n")
    ##############################################################
    with open("username.txt") as file:
        username = file.read()

    sec_log_call(f"{username} viewed HTTPS configuration")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} viewed HTTPS configuration")

    with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
        if os.stat("onossec.log").st_size != 0:
            lastline = firstfile.readlines()[-1].strip()
            secondfile.write(lastline + "\n")
            syslog.syslog(syslog.LOG_INFO, lastline)
    return render(request, "sdntool/viewhttp.html", {"ipconfiglist": ipstatuslist})


######### This method used for CONFIGURING TLS#################
def configtls(request):
    with open("iplist.txt", "r") as file:
        iplist = file.readlines()
    if request.method == "GET":
        return render(request, "sdntool/configtls.html", {"ip": iplist})
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
        return redirect(configtls)

    host = str(ip)
    port = 22
    username = request.POST.get("sshuser")  #'sdn'
    password = request.POST.get("sshpass")  #'cdcju'
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

        with sftp.open("/home/sdn/onosnew/bin/onos-service", "r") as file:
            data = file.readlines()  ###### reading all lines

        if status == "true":
            data[10] = (
                "export JAVA_OPTS="
                + '"'
                + "${JAVA_OPTS:--DenableOFTLS=true -Djavax.net.ssl.keyStore="
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
            messages.success(request, "Action Enabled")
        else:
            data[10] = (
                'export JAVA_OPTS="${JAVA_OPTS:--DenableOFTLS=false -Djavax.net.ssl.keyStore='
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
            messages.error(request, "Action Disabled")

        with sftp.open("/home/sdn/Documents/onos/bin/onos-service", "w") as file:
            file.writelines(data)

        sftp.close()
        ssh.close()
    except:
        messages.error(request, "Unable to connect with given IP")
        return redirect("configtls")
    with open("username.txt") as file:
        username = file.read()

    sec_log_call(f"{username} configured TLS")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} configured TLS")

    with open("onossec.log", "r") as firstfile, open("sds.log", "a") as secondfile:
        if os.stat("onossec.log").st_size != 0:
            lastline = firstfile.readlines()[-1].strip()
            secondfile.write(lastline + "\n")
            syslog.syslog(syslog.LOG_INFO, lastline)

    messages.info(request, "TLS configured")
    return redirect("viewtls")


######### This method used for modifying TLS configuration###########
def modifytls(request):

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
    username = "sdn"
    password = "cdcju"
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

        with sftp.open("/home/sdn/onosnew/bin/onos-service", "r") as file:
            data = file.readlines()  ###### reading all lines

        data[10] = (
            "export JAVA_OPTS="
            + '"'
            + "${JAVA_OPTS:--DenableOFTLS=true -Djavax.net.ssl.keyStore="
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

        with sftp.open("/home/sdn/onosnew/bin/onos-service", "w") as file:
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


######### This method used for disabling TLS##############
def disabletlsconfirm(request):
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
    username = "sdn"
    password = "cdcju"
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

        with sftp.open("/home/sdn/onosnew/bin/onos-service", "r") as file:
            data = file.readlines()  ###### reading all lines

        data[10] = data[10].replace("true", "false")
        with sftp.open("/home/sdn/onosnew/bin/onos-service", "w") as file:
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


ipconfiglist = list()


######### This method used for viewing TLS configuration#############
def viewtls(request):

    global ipconfiglist

    with open("userip.txt", "r") as file:
        ip = file.read()

    host = str(ip)
    port = 22
    username = "sdn"
    password = "cdcju"
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

        with sftp.open("/home/sdn/onosnew/bin/onos-service", "r") as file:
            data = file.readlines()  ###### reading all lines
    except:

        messages.error(request, "Unable to connect with given IP")
        return redirect("home")

    string = "true|false"
    status = re.findall(string, data[10])[0]

    sftp.close()
    ssh.close()

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


######## This method used for rendering form of add firewall rule#################
def addfire(request):

    with open("iplist.txt", "r") as file:

        iplist = file.readlines()

    if request.method == "GET":

        return render(request, "sdntool/addrulesip.html", {"ip": iplist})

    try:

        ip = request.POST.get("ip")
        with open("firewallip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP given as input")
        return redirect("addfire")
    try:
        deviceresponse = dict(
            requests.get(
                "http://" + str(ip) + ":8181/onos/v1/devices",
                auth=HTTPBasicAuth(onos_username, onos_password),
            ).json()
        )
    except:
        messages.error(request, "Wrong Ip selected or ONOS not running at the Ip")
        return redirect("addfire")

    return render(
        request, "sdntool/addfire.html", {"deviceresponse": deviceresponse, "ip": ip}
    )


##### This method used as controller for firewall rules#############
def addfirecontroller(request):
    ip = request.POST.get("ip")
    devid = request.POST.get("devid")
    protocol = request.POST.get("protocol")
    action = request.POST.get("action")
    requests.post(
        "http://"
        + str(ip)
        + ":8181/onos/firewall-app/firewall/add/all?action="
        + action
        + "&protocol="
        + protocol
        + "&deviceId="
        + devid,
        auth=HTTPBasicAuth(onos_username, onos_password),
    )  # api for posting

    messages.success(request, "Firewall rule added!")
    messages.info(request, "Firewall Management Configured")
    with open("username.txt") as file:
        username = file.read()
    log_call(f"{username} added firewall rule by source")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} added firewall rule by source")

    return redirect("viewrules")


######This method used for rendering form of firewall rules by port############
def addrulesbyport(request):
    with open("iplist.txt", "r") as file:

        iplist = file.readlines()

    if request.method == "GET":

        return render(request, "sdntool/addportrulesip.html", {"ip": iplist})

    try:

        ip = request.POST.get("ip")
        with open("firewallip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP given as input")
        return redirect("addrulesbyport")
    try:

        deviceresponse = dict(
            requests.get(
                "http://" + str(ip) + ":8181/onos/v1/devices",
                auth=HTTPBasicAuth(onos_username, onos_password),
            ).json()
        )
    except:
        messages.error(request, "Wrong Ip selected or ONOS not running at the Ip")
        return redirect("addrulesbyport")
    return render(
        request,
        "sdntool/addrulesbyport.html",
        {"deviceresponse": deviceresponse, "ip": ip},
    )


######### This method used as controller for adding firewall rule by ports#######
def addrulesbyportcontroller(request):
    ip = request.POST.get("ip")
    port = request.POST.get("port")
    devid = request.POST.get("devid")
    protocol = request.POST.get("protocol")
    action = request.POST.get("action")

    if not re.search("^[0-9]*$", port):
        messages.error(request, "Not a valid port")

        return redirect("addrulesbyport")

    requests.post(
        "http://"
        + str(ip)
        + ":"
        + str(port_num)
        + "/onos/firewall-app/firewall/add/byport?deviceId="
        + str(devid)
        + "&port="
        + port
        + "&protocol="
        + protocol
        + "&action="
        + action,
        auth=HTTPBasicAuth(onos_username, onos_password),
    )  # api for posting

    messages.success(request, "Firewall rule added!")
    messages.info(request, "Firewall Management Configured")
    with open("username.txt") as file:
        username = file.read()
    log_call(f"{username} added firewall rule by port")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} added firewall rule by port")

    return redirect("viewrules")


########## This method used for viewing firewall rules###############
def viewrules(request):
    with open("firewallip.txt", "r") as file:
        firewallip = file.read()

    try:
        response = requests.get(
            "http://"
            + firewallip
            + ":"
            + port_num
            + "/onos/firewall-app/firewall/rules",
            auth=HTTPBasicAuth(onos_username, onos_password),
        )
        firewallresponse = response.json()

    except:
        messages.error(request, "No Rules Added")
        return render(request, "sdntool/viewrules.html")

    with open("username.txt") as file:
        username = file.read()
    log_call(f"{username} viewed firewall rules")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} viewed firewall rules")

    return render(
        request, "sdntool/viewrules.html", {"firewallresponse": firewallresponse}
    )


###### This method used for deleting firewall rules###############
def deleterules(request, id):
    with open("firewallip.txt", "r") as file:
        firewallip = file.read()

    requests.delete(
        "http://" + firewallip + ":8181/onos/firewall-app/firewall/remove/" + id,
        auth=HTTPBasicAuth(onos_username, onos_password),
    )  # api for deleting

    return redirect("viewrules")


def disablentp(request):
    return render(request, "sdntool/disablentp.html")


def configntp(request):
    """
    Adding NTP server to the list of NTP servers
    """
    with open("iplist.txt", "r") as file:
        iplist = file.readlines()
    if request.method == "GET":
        return render(request, "sdntool/configntp.html", {"ip": iplist})
    server = request.POST.get("server")
    ip = request.POST.get("ip")
    username = request.POST.get("user")
    password = request.POST.get("password")
    try:
        with open("userip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP is given as input")
        return redirect("home")

    host = str(ip)
    port = 22
    # username = 'srijita'
    # password = 'cdcju'
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)
        sleeptime = 0.001
        outdata, errdata = b"", b""
        ssh_transp = ssh.get_transport()
        chan = ssh_transp.open_session()
        # chan.settimeout(3 * 60 * 60)
        chan.setblocking(0)
        chan.exec_command(f"sudo -S ntpdate {server}")
        chan.send(f"{password}\n".encode("utf-8"))
        while True:  # monitoring process
            # Reading from output streams
            while chan.recv_ready():
                outdata += chan.recv(1000)
            while chan.recv_stderr_ready():
                errdata += chan.recv_stderr(1000)
            if chan.exit_status_ready():  # If completed
                break
            time.sleep(sleeptime)
        retcode = chan.recv_exit_status()
        ssh_transp.close()
    except Exception as e:
        print(e)
        messages.error(request, "Unable to connect remotely")
        return redirect("home")
    print(outdata, errdata)
    with open("username.txt") as file:
        username = file.read()
    with open("ntpdata.json", "r") as f:
        try:
            d = json.loads(f.read())
        except Exception:
            d = []
    for idx, di in enumerate(d):
        if di["ip"] == ip:
            di["server"] = server
            di["comment"] = outdata.decode("utf-8")
            d[idx] = di

    if {"server": server, "ip": ip, "comment": outdata.decode("utf-8")} not in d:
        d.append({"server": server, "ip": ip, "comment": outdata.decode("utf-8")})
    with open("ntpdata.json", "w") as f:
        f.write(json.dumps(d))
    sec_log_call(f"{username} configured NTP on {ip} with {server}")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} configured NTP on {ip} with {server}")

    messages.info(request, f"IP:{ip} Configured with NTP server")
    return render(request, "sdntool/ntp.html")


ddoscnt = 0


########### This method used for viewing ddos attacks##########
def ddos(request):

    portfaultcounter = 0

    if os.stat("portconf.json").st_size == 0:  ##### checking if file is empty

        portapi = dict(
            requests.get(
                "http://192.168.0.24:8181/onos/v1/devices/ports",
                auth=HTTPBasicAuth(onos_username, onos_password),
            ).json()
        )

        ####################### Storing only enabled ports in json file##########################
        for i in portapi["ports"]:
            if i["isEnabled"] == False:
                portapi["ports"].remove(i)

        port_json = json.dumps(portapi)

        with open("portconf.json", "w") as outfile:
            outfile.write(port_json)
        outfile.close()

    #################################################################################

    ##################### READING STORED JSON AND VERIFYING AGAINST THE API IF PRESENT ##############################
    with open("portconf.json") as portconfig_file:
        portdata = portconfig_file.read()
    portconfiguration = json.loads((portdata))

    portfaultresponse = list()

    allportapi = dict(
        requests.get(
            "http://192.168.0.24:8181/onos/v1/devices/ports",
            auth=HTTPBasicAuth(onos_username, onos_password),
        ).json()
    )

    for i in portconfiguration["ports"]:

        flag = 0
        for j in allportapi["ports"]:

            if (i["annotations"]["portMac"] == j["annotations"]["portMac"]) and (
                i["isEnabled"] == j["isEnabled"]
            ):
                flag = flag + 1
        if flag == 0:

            portfaultresponse.append({"id": i["element"], "port": i["port"]})
            portfaultcounter = portfaultcounter + 1

    print("portfaultresponse")
    print(portfaultresponse)
    if portfaultcounter == 0:
        messages.success(request, "No DDOS detected")
    else:
        messages.error(request, "DDOS attack detected!")

    return render(
        request,
        "sdntool/DDOSattack.html",
        {"portfaultresponse": portfaultresponse, "portfaultcounter": portfaultcounter},
    )


def ntp(request):
    """
    View for NTP configuration
    """
    try:
        with open("ntpdata.json", "r") as f:
            data = json.loads(f.read())

    except Exception:
        data = []
    return render(request, "sdntool/ntp.html", {"data": data})


def addscrulesip(request):
    """
    View for adding firewall rules by source and destination
    """
    return render(request, "sdntool/addscrulesip.html")


def addrulesbysrc(request):
    """
    View for adding firewall rules by source
    """
    with open("iplist.txt", "r") as file:

        iplist = file.readlines()

    if request.method == "GET":
        return render(request, "sdntool/addrulessrcip.html", {"ip": iplist})
    try:
        ip = request.POST.get("ip")
        with open("firewallip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP given as input")
        return redirect("addrulesbysrc")

    try:
        hostresponse = dict(
            requests.get(
                "http://" + str(ip) + ":8181/onos/v1/hosts",
                auth=HTTPBasicAuth(onos_username, onos_password),
            ).json()
        )
    except:
        messages.error(request, "Wrong Ip selected or ONOS not running at the Ip")
        return redirect("addrulesbysrc")

    return render(
        request, "sdntool/addrulesbysrc.html", {"ip": ip, "hostresponse": hostresponse}
    )


def addrulesbysrccontroller(request):
    """
    Controller for adding firewall rules by source
    """
    ip = request.POST.get("ip")

    protocol = request.POST.get("protocol")
    action = request.POST.get("action")
    src = request.POST.get("src")
    dst = request.POST.get("dst")

    if src == dst:

        messages.error(
            request, "Please enter different source and destination mac addresses"
        )

        return redirect("addrulesbysrc")

    requests.post(
        "http://"
        + str(ip)
        + ":8181/onos/firewall-app/firewall/add/bysrc?sourceMac="
        + src
        + "&destMac="
        + dst
        + "&protocol="
        + protocol
        + "&action="
        + action,
        auth=HTTPBasicAuth(onos_username, onos_password),
    )  # api for posting

    messages.success(request, "Firewall rule added!")
    messages.info(request, "Firewall Management Configured")
    with open("username.txt") as file:
        username = file.read()
    log_call(f"{username} added firewall rule by source")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} added firewall rule by source")

    return redirect("viewrules")
