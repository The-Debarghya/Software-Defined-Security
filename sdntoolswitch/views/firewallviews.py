import json
import re
import syslog
import requests
from requests.auth import HTTPBasicAuth
from django.shortcuts import redirect, render
from django.contrib import messages
from sdntoolswitch.activitylogs import *
from sdntoolswitch.onosseclogs import *
from sdntoolswitch.aaalogs import *

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

def addfire(request):
    """
    View for adding firewall rules
    """
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
        global onos_username
        global onos_password
        with open("config.json", "r") as file:
            config = json.load(file)
            onos_username = config["onos_user"]
            onos_password = config["onos_pwd"]
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


def addfirecontroller(request):
    """
    Controller for adding firewall rule
    """
    ip = request.POST.get("ip")
    devid = request.POST.get("devid")
    protocol = request.POST.get("protocol")
    action = request.POST.get("action")
    global onos_username
    global onos_password
    with open("config.json", "r") as file:
        config = json.load(file)
        onos_username = config["onos_user"]
        onos_password = config["onos_pwd"]
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


def addrulesbyport(request):
    """
    View for adding firewall rules by port
    """
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
        global onos_username
        global onos_password
        global port_num
        with open("config.json", "r") as file:
            config = json.load(file)
            onos_username = config["onos_user"]
            onos_password = config["onos_pwd"]
            port_num = config["port_num"]
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


def addrulesbyportcontroller(request):
    """
    Controller for adding firewall rules by port
    """
    ip = request.POST.get("ip")
    port = request.POST.get("port")
    devid = request.POST.get("devid")
    protocol = request.POST.get("protocol")
    action = request.POST.get("action")

    if not re.search("^[0-9]*$", port):
        messages.error(request, "Not a valid port")

        return redirect("addrulesbyport")
    global onos_username
    global onos_password
    global port_num
    with open("config.json", "r") as file:
        config = json.load(file)
        onos_username = config["onos_user"]
        onos_password = config["onos_pwd"]
        port_num = config["port_num"]
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


def viewrules(request):
    """
    Viewing firewall rules
    """
    with open("firewallip.txt", "r") as file:
        firewallip = file.read()
    global onos_username
    global onos_password
    global port_num
    with open("config.json", "r") as file:
        config = json.load(file)
        onos_username = config["onos_user"]
        onos_password = config["onos_pwd"]
        port_num = config["port_num"]
    try:
        response = requests.get(
            "http://"
            + firewallip
            + ":"
            + str(port_num)
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


def deleterules(request, id):
    """
    Deleting firewall rule by id
    """
    with open("firewallip.txt", "r") as file:
        firewallip = file.read()
    global onos_username
    global onos_password
    with open("config.json", "r") as file:
        config = json.load(file)
        onos_username = config["onos_user"]
        onos_password = config["onos_pwd"]
    requests.delete(
        "http://" + firewallip + ":8181/onos/firewall-app/firewall/remove/" + id,
        auth=HTTPBasicAuth(onos_username, onos_password),
    )  # api for deleting

    return redirect("viewrules")

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
    global onos_username
    global onos_password
    with open("config.json", "r") as file:
        config = json.load(file)
        onos_username = config["onos_user"]
        onos_password = config["onos_pwd"]
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
    global onos_username
    global onos_password
    with open("config.json", "r") as file:
        config = json.load(file)
        onos_username = config["onos_user"]
        onos_password = config["onos_pwd"]
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