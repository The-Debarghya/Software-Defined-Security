import json
import re
import syslog
import requests
from requests.auth import HTTPBasicAuth
from django.shortcuts import redirect, render
from django.contrib import messages
from django.views.decorators.cache import cache_control
from sdntoolswitch.activitylogs import *
from sdntoolswitch.models import OnosServerManagement
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.onosseclogs import *
from sdntoolswitch.aaalogs import *

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addfire(request):
    """
    View for adding firewall rules
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = [config["ip"] for config in json.loads(onosServerRecord.multipleconfigjson)]
    except:
        iplist = []

    if request.method == "GET":
        return render(request, "sdntool/addrulesip.html", {"ip": iplist})

    try:
        ip = request.POST.get("ip")
        record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
        host = str(record.primaryip)
        if ip == host:
            pass
        else:
            raise Exception
    except:
        messages.error(request, "No IP given as input")
        return redirect("addfire")
    try:
        username = request.session["login"]["username"]
        record = OnosServerManagement.objects.get(usercreated=username)
        configarr = json.loads(record.multipleconfigjson)
        config = [i for i in configarr if i["ip"] == ip][0]
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

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addfirecontroller(request):
    """
    Controller for adding firewall rule
    """
    ip = request.POST.get("ip")
    devid = request.POST.get("devid")
    protocol = request.POST.get("protocol")
    action = request.POST.get("action")
    username = request.session["login"]["username"]
    record = OnosServerManagement.objects.get(usercreated=username)
    configarr = json.loads(record.multipleconfigjson)
    config = [i for i in configarr if i["ip"] == ip][0]
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
    log_call(f"{username} added firewall rule by source")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} added firewall rule by source")

    return redirect("viewrules")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addrulesbyport(request):
    """
    View for adding firewall rules by port
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = [config["ip"] for config in json.loads(onosServerRecord.multipleconfigjson)]
    except:
        iplist = []

    if request.method == "GET":

        return render(request, "sdntool/addportrulesip.html", {"ip": iplist})

    try:

        ip = request.POST.get("ip")
        record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
        host = str(record.primaryip)
        if ip == host:
            pass
        else:
            raise Exception
    except:
        messages.error(request, "No IP given as input")
        return redirect("addrulesbyport")
    try:
        username = request.session["login"]["username"]
        record = OnosServerManagement.objects.get(usercreated=username)
        configarr = json.loads(record.multipleconfigjson)
        config = [i for i in configarr if i["ip"] == ip][0]
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
        return redirect("addrulesbyport")
    return render(
        request,
        "sdntool/addrulesbyport.html",
        {"deviceresponse": deviceresponse, "ip": ip},
    )

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
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
    username = request.session["login"]["username"]
    record = OnosServerManagement.objects.get(usercreated=username)
    configarr = json.loads(record.multipleconfigjson)
    config = [i for i in configarr if i["ip"] == ip][0]
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
    log_call(f"{username} added firewall rule by port")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} added firewall rule by port")

    return redirect("viewrules")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def viewrules(request):
    """
    Viewing firewall rules
    """
    record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
    firewallip = str(record.primaryip)
    username = request.session["login"]["username"]
    record = OnosServerManagement.objects.get(usercreated=username)
    configarr = json.loads(record.multipleconfigjson)
    config = [i for i in configarr if i["ip"] == firewallip][0]
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

    log_call(f"{username} viewed firewall rules")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} viewed firewall rules")

    return render(
        request, "sdntool/viewrules.html", {"firewallresponse": firewallresponse}
    )

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def deleterules(request, id):
    """
    Deleting firewall rule by id
    """
    record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
    firewallip = str(record.primaryip)
    username = request.session["login"]["username"]
    record = OnosServerManagement.objects.get(usercreated=username)
    configarr = json.loads(record.multipleconfigjson)
    config = [i for i in configarr if i["ip"] == firewallip][0]
    onos_username = config["onos_user"]
    onos_password = config["onos_pwd"]
    requests.delete(
        "http://" + firewallip + ":8181/onos/firewall-app/firewall/remove/" + id,
        auth=HTTPBasicAuth(onos_username, onos_password),
    )  # api for deleting

    return redirect("viewrules")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addscrulesip(request):
    """
    View for adding firewall rules by source and destination
    """
    return render(request, "sdntool/addscrulesip.html")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addrulesbysrc(request):
    """
    View for adding firewall rules by source
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = [config["ip"] for config in json.loads(onosServerRecord.multipleconfigjson)]
    except:
        iplist = []

    if request.method == "GET":
        return render(request, "sdntool/addrulessrcip.html", {"ip": iplist})
    try:
        ip = request.POST.get("ip")
        record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
        host = str(record.primaryip)
        if ip == host:
            pass
        else:
            raise Exception
    except:
        messages.error(request, "No IP given as input")
        return redirect("addrulesbysrc")
    record = OnosServerManagement.objects.get(usercreated=username)
    configarr = json.loads(record.multipleconfigjson)
    config = [i for i in configarr if i["ip"] == ip][0]
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

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
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
    username = request.session["login"]["username"]
    record = OnosServerManagement.objects.get(usercreated=username)
    configarr = json.loads(record.multipleconfigjson)
    config = [i for i in configarr if i["ip"] == ip][0]
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
    log_call(f"{username} added firewall rule by source")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} added firewall rule by source")

    return redirect("viewrules")