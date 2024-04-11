import json
import os
import time
import paramiko
import requests
import logging
from requests.auth import HTTPBasicAuth
from django.shortcuts import redirect, render
from django.contrib import messages
from django.views.decorators.cache import cache_control
from sdntoolswitch.models import OnosServerManagement, NtpConfigRecords
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.generic_logger import logger_call, create_logger

logger = create_logger(__package__.rsplit(".", 1)[-1], file_name="onossec.log")


@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def disablentp(request):
    return render(request, "sdntool/disablentp.html")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def configntp(request):
    """
    Adding NTP server to the list of NTP servers
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = [config["ip"] for config in json.loads(onosServerRecord.multipleconfigjson)]
    except:
        iplist = []
    if request.method == "GET":
        return render(request, "sdntool/configntp.html", {"ip": iplist})
    server = request.POST.get("server")
    ip = request.POST.get("ip")
    sshuser = request.POST.get("user")
    password = request.POST.get("password")
    try:
        record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
        primaryip = str(record.primaryip)
        if ip == primaryip:
            pass
        else:
            raise Exception
    except:
        logger.warn("No IP is given as input")
        messages.error(request, "No IP is given as input")
        return redirect("home")

    host = str(ip)
    port = 22
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, port=port, username=sshuser, password=password)
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
        logger.warn(f"Unable to connect remotely, {e.__str__()}")
        messages.error(request, "Unable to connect remotely")
        return redirect("home")
    print(outdata, errdata)
    username = request.session["login"]["username"]
    record = NtpConfigRecords.objects.get(usercreated=username, ip=ip)
    if record is not None:
        if record.ntpserver == server:
            record.output = outdata.decode("utf-8")
            record.save()
        else:
            record.ntpserver = server
            record.output = outdata.decode("utf-8")
            record.save()
    else:
        data = NtpConfigRecords.objects.create(
            ntpserver=server, ip=ip, usercreated=username, output=outdata.decode("utf-8")
        )
        data.save()
    logger.info(f"{username} configured NTP on {ip} with {server}")

    messages.info(request, f"IP:{ip} Configured with NTP server")
    return render(request, "sdntool/ntp.html")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def ddos(request):
    """
    View for DDOS attack detection
    """
    portfaultcounter = 0
    record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
    ip = str(record.primaryip)
    if os.stat("portconf.json").st_size == 0:
        username = request.session["login"]["username"]
        record = OnosServerManagement.objects.get(usercreated=username)
        configarr = json.loads(record.multipleconfigjson)
        config = [i for i in configarr if i["ip"] == ip][0]
        onos_username = config["onos_user"]
        onos_password = config["onos_pwd"]
        portapi = dict(
            requests.get(
                f"http://{ip}:8181/onos/v1/devices/ports",
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

    ##################### READING STORED JSON AND VERIFYING AGAINST THE API IF PRESENT ##############################
    with open("portconf.json") as portconfig_file:
        portdata = portconfig_file.read()
    portconfiguration = json.loads((portdata))

    portfaultresponse = list()
    username = request.session["login"]["username"]
    record = OnosServerManagement.objects.get(usercreated=username)
    configarr = json.loads(record.multipleconfigjson)
    config = [i for i in configarr if i["ip"] == ip][0]
    onos_username = config["onos_user"]
    onos_password = config["onos_pwd"]
    allportapi = dict(
        requests.get(
            f"http://{ip}:8181/onos/v1/devices/ports",
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

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def ntp(request):
    """
    View for NTP configuration
    """
    try:
        username = request.session["login"]["username"]
        data = NtpConfigRecords.objects.filter(usercreated=username).values()
        if data is None:
            data = []
        else:
            data = list(data)
            data = [{"server": i[0], "ip": i[1], "output": i[3]} for i in data]
    except Exception:
        data = []
    logger_call(logging.INFO, f"{username} monitored NTP details", file_name="sds.log")
    return render(request, "sdntool/ntp.html", {"data": data})

