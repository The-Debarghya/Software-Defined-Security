import os
import re
import paramiko
import requests
import syslog
from django.shortcuts import redirect, render
from django.contrib import messages
from sdntoolswitch.activitylogs import *
from sdntoolswitch.onosseclogs import *
from sdntoolswitch.aaalogs import *

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

def confighttp(request):
    """
    View for configuring HTTPS
    """
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
        karaf_ver = request.POST.get("karaf")
        with sftp.open(
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.ops4j.pax.web.cfg",
            "r",
        ) as file:
            data = file.readlines()  ###### reading all lines
        for i in range(len(data)):
            if data[i].startswith("org.ops4j.pax.web.ssl.keystore"):
                data[i] = "org.ops4j.pax.web.ssl.keystore=" + keyloc + "\n"
            elif data[i].startswith("org.ops4j.pax.web.ssl.password"):
                data[i] = "org.ops4j.pax.web.ssl.password=" + httppassword + "\n"
            elif data[i].startswith("org.ops4j.pax.web.ssl.keypassword"):
                data[i] = "org.ops4j.pax.web.ssl.keypassword=" + cnfpassword + "\n"
            elif data[i].startswith("org.osgi.service.http.secure.enabled"):
                if status == "true":
                    data[i] = 'org.osgi.service.http.secure.enabled="+true+"\n'
                    messages.success(request, "Action Enabled")
                else:
                    data[i] = "org.osgi.service.http.secure.enabled=false\n"
                    messages.error(request, "Action Disabled")

        with open(
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.ops4j.pax.web.cfg",
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


def modifyhttp(request):
    """
    View for modifying HTTPS
    """
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
    onos_location = request.POST.get("fileloc")
    karaf_ver = request.POST.get("karaf")
    try:
        with open("userip.txt", "w") as file:
            file.write(ip)
    except:
        messages.error(request, "No IP is given as input")
        return redirect("modifyhttp")

    host = str(ip)
    port = 22
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password)

    except paramiko.AuthenticationException:
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
        full_path = (
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.ops4j.pax.web.cfg"
        )
        with sftp.open(full_path, "w") as f:
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
    """
    View for disabling HTTPS
    """
    if request.method == "GET":
        return render(request, "sdntool/disablehttp.html")


def disablehttpconfirm(request):
    """
    Controller for disabling HTTPS
    """
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
        karaf_ver = request.POST.get("karaf")
        with sftp.open(
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.ops4j.pax.web.cfg",
            "r",
        ) as file:
            data = str(file.read())
        re.sub(
            r"org.osgi.service.http.secure.enabled=true",
            "org.osgi.service.http.secure.enabled=false",
            data,
        )

        with sftp.open(
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.ops4j.pax.web.cfg",
            "w",
        ) as file:
            file.writelines(data)
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


def viewhttp(request):
    """
    View for viewing HTTPS configuration
    """
    global ipconfiglist

    with open("userip.txt", "r") as file:
        ip = file.read()

    host = str(ip)
    try:
        resp = requests.get(f"https://{host}:8443/onos/ui/login.html", verify=False)
        status = True
    except ConnectionRefusedError:
        status = False
    except:
        status = False
    if status is True:
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