import json
import re
import paramiko
import requests
import logging
from django.shortcuts import redirect, render
from django.contrib import messages
from django.views.decorators.cache import cache_control
from sdntoolswitch.models import OnosServerManagement
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.generic_logger import logger_call, create_logger

logger = create_logger(__package__.rsplit(".", 1)[-1], file_name="onossec.log")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def modifyhttp(request):
    """
    View for modifying HTTPS
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []
    if request.method == "GET":
        return render(request, "sdntool/modifyhttp.html", {"ip": iplist})
    status = request.POST.get("status")
    keyloc = request.POST.get("key")
    httppassword = request.POST.get("password")
    cnfpassword = request.POST.get("cnfpassword")
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
        return redirect("modifyhttp")

    host = str(ip)
    port = onosconfig["ssh_port"]
    sshuser = onosconfig["onos_user"]
    password = onosconfig["onos_pwd"]
    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=sshuser, password=password)

    except paramiko.AuthenticationException:
        logger.warning("Authentication failed, please verify your credentials")
        messages.error(
            request,
            "Authentication failed, please verify your credentials: %s"
            % paramiko.AuthenticationException,
        )
        return redirect("home")
    except paramiko.BadHostKeyException as badHostKeyException:
        logger.warning("Unable to verify server's host key")
        messages.error(
            request, "Unable to verify server's host key: %s" % badHostKeyException
        )
        return redirect("home")

    except paramiko.SSHException as sshException:
        logger.warning("Unable to establish SSH connection")
        messages.error(request, "Unable to establish SSH connection: %s" % sshException)
        return redirect("home")

    # Create SFTP client
    sftp = ssh.open_sftp()
    try:
        datatowrite = """
                org.osgi.service.http.port=8181
                org.osgi.service.http.port.secure=8443
                org.osgi.service.http.enabled=true
                org.osgi.service.http.secure.enabled={}
                org.ops4j.pax.web.ssl.keystore={}
                org.ops4j.pax.web.ssl.password={}
                org.ops4j.pax.web.ssl.keypassword={}
                org.ops4j.pax.web.session.timeout=1440
                org.ops4j.pax.web.session.url=none
                org.ops4j.pax.web.config.file=./etc/jetty.xml
                """.format(
            status, keyloc, httppassword, cnfpassword
        )
        onos_location = onosconfig["file_loc"]
        karaf_ver = onosconfig["karaf_ver"]
        full_path = (
            f"{onos_location}/apache-karaf-{karaf_ver}/etc/org.ops4j.pax.web.cfg"
        )
        with sftp.open(full_path, "w") as f:
            f.writelines(datatowrite)
        sftp.close()
        ssh.close()
    except Exception as e:
        logger.warning(f"Unable to connect with given IP, {e.__str__()}")
        messages.error(request, "Unable to connect with given IP")
        return redirect("modifyhttp")

    if httppassword == cnfpassword:
        username = request.session["login"]["username"]
        msg = f"{username} modified HTTPS"
        logger_call(logging.INFO, msg, file_name="sds.log")
        logger.info(msg)

        messages.info(request, "HTTPS configuration modified")
        return redirect("viewhttp")
    else:
        messages.error(request, "Password and confirmed passwords do not match")
        return redirect("modifyhttp")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def disablehttp(request):
    """
    View for disabling HTTPS
    """
    if request.method == "GET":
        return render(request, "sdntool/disablehttp.html")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def disablehttpconfirm(request):
    """
    Controller for disabling HTTPS
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []
    if request.method == "GET":
        return render(request, "sdntool/disablehttpip.html", {"ip": iplist})
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
        return redirect("httpdisableconfirm")

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
        karaf_ver = onosconfig["karaf_ver"]
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
        logger.warning("Unable to connect with given IP")
        messages.error(request, "Unable to connect with given IP")
        return redirect("httpdisableconfirm")
    username = request.session["login"]["username"]

    msg = f"{username} disabled HTTPS"
    logger_call(logging.INFO, msg, file_name="sds.log")
    logger.info(msg)
    messages.error(request, "HTTPS disabled")
    return redirect("viewhttp")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def viewhttp(request):
    """
    View for viewing HTTPS configuration
    """
    global ipconfiglist
    ipconfiglist = []

    record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
    iplist = record.iplist.split(",")
    for ip in iplist:
        host = str(ip)
        try:
            resp = requests.get(f"https://{host}:8443/onos/ui/login.html", verify=False)
            status = True
        except ConnectionRefusedError:
            status = False
        except Exception as e:
            logger.warning(f"Unable to connect with given IP, {e.__str__()}")
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
    username = request.session["login"]["username"]

    msg = f"{username} viewed HTTPS configuration"
    logger_call(logging.INFO, msg, file_name="sds.log")
    logger.info(msg)
    return render(request, "sdntool/viewhttp.html", {"ipconfiglist": newipconfiglist})