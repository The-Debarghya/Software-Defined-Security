import json
import re
import requests
import logging
from requests.auth import HTTPBasicAuth
from django.shortcuts import redirect, render
from django.contrib import messages
from django.views.decorators.cache import cache_control
from sdntoolswitch.models import OnosServerManagement
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.role_validator import admin_manager_check
from sdntoolswitch.generic_logger import logger_call, create_logger

logger = create_logger(__package__.rsplit(".", 1)[-1], file_name="onossec.log")


@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addfire(request):
    """
    View for adding firewall rules
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []
    if request.method == "GET":
        return render(request, "sdntool/addrulesip.html", {"ip": iplist})
    try:
        ip = request.POST.get("ip")
        if ip != "":
            pass
        else:
            raise Exception
    except:
        logger.warning("No IP given as input")
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
        logger_call(
            logging.ERROR,
            "Wrong Ip selected or ONOS not running at the Ip",
            file_name="err.log",
        )
        messages.error(request, "Wrong Ip selected or ONOS not running at the Ip")
        return redirect("addfire")
    return render(
        request, "sdntool/addfire.html", {"deviceresponse": deviceresponse, "ip": ip}
    )


@login_check
@admin_manager_check
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
    msg = f"{username} added firewall rule by source"
    logger_call(logging.INFO, msg, file_name="sds.log")

    return redirect("viewrules")


@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addrulesbyport(request):
    """
    View for adding firewall rules by port
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []

    if request.method == "GET":
        return render(request, "sdntool/addportrulesip.html", {"ip": iplist})

    try:
        ip = request.POST.get("ip")
        if ip != "":
            pass
        else:
            raise Exception
    except:
        logger.warning("No IP given as input")
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
        logger_call(
            logging.ERROR,
            "Wrong Ip selected or ONOS not running at the Ip",
            file_name="err.log",
        )
        messages.error(request, "Wrong Ip selected or ONOS not running at the Ip")
        return redirect("addrulesbyport")
    return render(
        request,
        "sdntool/addrulesbyport.html",
        {"deviceresponse": deviceresponse, "ip": ip},
    )


@login_check
@admin_manager_check
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
    msg = f"{username} added firewall rule by port"
    logger_call(logging.INFO, msg, file_name="sds.log")

    return redirect("viewrules")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def viewrules(request):
    """
    Viewing firewall rules
    """
    record = OnosServerManagement.objects.get(
        usercreated=request.session["login"]["username"]
    )
    firewallresponse = []
    configarr = json.loads(record.multipleconfigjson)
    for config in configarr:
        firewallip = config["ip"]
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
            firewallresponse.append({"ip": firewallip, "rules": response.json()})
        except:
            logger.warning("No Rules Added")
            messages.error(request, "No Rules Added")
            firewallresponse.append({"ip": firewallip, "rules": []})
    username = request.session["login"]["username"]
    msg = f"{username} viewed firewall rules"
    logger_call(logging.INFO, msg, file_name="sds.log")
    return render(
        request, "sdntool/viewrules.html", {"firewallresponse": firewallresponse}
    )


@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def deleterules(request):
    """
    Deleting firewall rule by id
    """
    record = OnosServerManagement.objects.get(
        usercreated=request.session["login"]["username"]
    )
    firewallip = request.GET.get("firewallip", "")
    id = request.GET.get("id", "")
    if id == "" or firewallip == "":
        messages.error(request, "No id/IP given as input")
        return redirect("viewrules")
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
    username = request.session["login"]["username"]
    msg = f"{username} deleted firewall rule"
    logger_call(logging.INFO, msg, file_name="sds.log")
    return redirect("viewrules")


@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addscrulesip(request):
    """
    View for adding firewall rules by source and destination
    """
    return render(request, "sdntool/addscrulesip.html")


@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def addrulesbysrc(request):
    """
    View for adding firewall rules by source
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []

    if request.method == "GET":
        return render(request, "sdntool/addrulessrcip.html", {"ip": iplist})
    try:
        ip = request.POST.get("ip")
        if ip != "":
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
        logger.warning("Wrong Ip selected or ONOS not running at the Ip")
        messages.error(request, "Wrong Ip selected or ONOS not running at the Ip")
        return redirect("addrulesbysrc")

    return render(
        request, "sdntool/addrulesbysrc.html", {"ip": ip, "hostresponse": hostresponse}
    )


@login_check
@admin_manager_check
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
    logger_call(logging.INFO, f"{username} added firewall rule by source", file_name="sds.log")
    return redirect("viewrules")
