import json
import re
import requests
import syslog
from django.shortcuts import redirect, render
from django.contrib import messages
from requests.auth import HTTPBasicAuth
from sdntoolswitch.activitylogs import *
from sdntoolswitch.onosseclogs import *
from sdntoolswitch.aaalogs import *

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

def aaa(request):
    """
    View for AAA page
    """
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


def aaacontroller(request):
    """
    Controller for AAA page
    """
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

    url = f"http://{ip}:8181/onos/v1/network/configuration"
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
    headers = {"Content-Type": "application/json"}
    global onos_username
    global onos_password
    with open("config.json", "r") as file:
        config = json.load(file)
        onos_username = config["onos_user"]
        onos_password = config["onos_pwd"]
    requests.post(
        url=url,
        data=aaaconfigjson,
        headers=headers,
        auth=HTTPBasicAuth(onos_username, onos_password),
    )

    with open("username.txt") as file:
        username = file.read()

    aaalog_call(f"{username} configured AAA")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} configured AAA")
    messages.info(request, "AAA configured")
    return redirect("viewradius")


def viewradius(request):
    """
    View for viewing radius server
    """
    with open("userip.txt", "r") as file:
        ip = file.read()
    host = str(ip)
    global onos_username
    global onos_password
    with open("config.json", "r") as file:
        config = json.load(file)
        onos_username = config["onos_user"]
        onos_password = config["onos_pwd"]
    response = requests.get(
        f"http://{host}:8181/onos/v1/network/configuration",
        auth=HTTPBasicAuth(onos_username, onos_password),
    )
    config = json.loads(response)  ####### reading the json file

    radiusip = config["apps"]["org.opencord.aaa"]["AAA"]["radiusIp"]
    with open("username.txt") as file:
        username = file.read()
    aaalog_call(f"{username} viewed AAA")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} viewed AAA")
    return render(request, "sdntool/viewradius.html", {"radius": radiusip})
