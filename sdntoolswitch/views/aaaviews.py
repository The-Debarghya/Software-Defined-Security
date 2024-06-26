import json
import logging
import re
import requests
from django.shortcuts import redirect, render
from django.contrib import messages
from django.views.decorators.cache import cache_control
from requests.auth import HTTPBasicAuth
from sdntoolswitch.models import OnosServerManagement
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.role_validator import admin_manager_check
from sdntoolswitch.generic_logger import logger_call

@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def aaa(request):
    """
    View for AAA page
    """
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = onosServerRecord.iplist.split(",")
    except:
        iplist = []

    if request.method == "GET":
        return render(request, "sdntool/aaaip.html", {"ip": iplist})

    ip = request.POST.get("ip")
    return render(request, "sdntool/configureradius.html", {"ip": ip})

@login_check
@admin_manager_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
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
    username = request.session["login"]["username"]
    record = OnosServerManagement.objects.get(usercreated=username)
    configarr = json.loads(record.multipleconfigjson)
    config = [i for i in configarr if i["ip"] == ip][0]
    onos_username = config["onos_user"]
    onos_password = config["onos_pwd"]
    requests.post(
        url=url,
        data=aaaconfigjson,
        headers=headers,
        auth=HTTPBasicAuth(onos_username, onos_password),
    )

    msg = f"{username} configured AAA"
    logger_call(logging.INFO, msg, file_name="sds.log")
    messages.info(request, "AAA configured")
    return redirect("viewradius")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def viewradius(request):
    """
    View for viewing radius server
    """
    record = OnosServerManagement.objects.get(usercreated=request.session["login"]["username"])
    configlist = json.loads(record.multipleconfigjson)
    radiuslist = []
    for config in configlist:
        host = config["ip"]
        onos_username = config["onos_user"]
        onos_password = config["onos_pwd"]    
        try:
            response = requests.get(
                f"http://{host}:8181/onos/v1/network/configuration",
                auth=HTTPBasicAuth(onos_username, onos_password),
            )
            config = response.json()  ####### reading the json file
            radiusip = config["apps"]["org.opencord.aaa"]["AAA"]["radiusIp"]
            radiuslist.append(radiusip)
        except Exception as e:
            radiusip = ""
            logger_call(logging.ERROR, f"Error in viewing radius: {e.__str__()}", file_name="aaa.log")

    username = request.session["login"]["username"]
    msg = f"{username} viewed AAA"
    logger_call(logging.INFO, msg, file_name="sds.log")
    return render(request, "sdntool/viewradius.html", {"radiuslist": radiuslist})
