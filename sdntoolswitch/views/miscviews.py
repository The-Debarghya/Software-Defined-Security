import json
import os
import syslog
import time
import paramiko
import requests
from requests.auth import HTTPBasicAuth
from django.shortcuts import redirect, render
from django.contrib import messages
from sdntoolswitch.activitylogs import *
from sdntoolswitch.onosseclogs import *
from sdntoolswitch.aaalogs import *

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

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


def ddos(request):
    """
    View for DDOS attack detection
    """
    portfaultcounter = 0
    with open("iplist.txt", "r") as file:
        ip = str(file.read())
    if os.stat("portconf.json").st_size == 0:
        with open("config.json", "r") as file:
            config = json.load(file)
        onos_username = config["onos_user"] if "onos_user" in config.keys() else "onos"
        onos_password = config["onos_pwd"] if "onos_pwd" in config.keys() else "rocks"
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
    with open("config.json", "r") as file:
        config = json.load(file)
        onos_username = config["onos_user"] if "onos_user" in config.keys() else "onos"
        onos_password = config["onos_pwd"] if "onos_pwd" in config.keys() else "rocks"
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

