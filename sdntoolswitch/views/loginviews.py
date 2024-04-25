import json
import logging
from django.shortcuts import redirect, render
from django.contrib import messages
from django.contrib.auth.hashers import check_password
from django.views.decorators.cache import cache_control
from sdntoolswitch.models import OnosServerManagement, Usermanagement, NtpConfigRecords, DeviceConfigRecords
from sdntoolswitch.formvalidation import Validator
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.generic_logger import logger_call


def login(request):
    """
    View for login page
    """
    return render(request, "sdntool/login.html")


def logincontroller(request):
    """
    Controller for login page
    """
    global username
    global password
    username = request.POST.get("username")
    password = request.POST.get("password")

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
                    logger_call(logging.INFO, f"{username} logged in", file_name="sds.log")
                    return redirect("configcontroller")
                else:
                    logger_call(logging.INFO, f"{username} logged in", file_name="sds.log")
                    return redirect("home")

            else:
                messages.error(
                    request, "Your password is not correct", extra_tags="loginerror"
                )
                return redirect("login")
        else:
            messages.error(request, "User does not exist", extra_tags="loginerror")
            return redirect("login")


def logout(request):
    """
    Controller for logout
    """
    global username
    username = request.session["login"]["username"]
    del request.session["login"]
    NtpConfigRecords.objects.filter(usercreated=username).delete()
    DeviceConfigRecords.objects.filter(usercreated=username).delete()
    with open("portconf.json", "w") as file:
        file.truncate()
    logger_call(logging.INFO, f"{username} logged out", file_name="sds.log")
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
    username = request.session["login"]["username"]
    onosServerRecord = OnosServerManagement.objects.get(usercreated=username)
    try:
        iplist = json.loads(onosServerRecord.multipleconfigjson)
    except:
        iplist = []

    username = request.session["login"]["username"]
    return render(request, "sdntool/home.html", {"iplist": iplist, "title": data["title"]})