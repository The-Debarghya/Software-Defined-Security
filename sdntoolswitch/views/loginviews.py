import syslog
from django.shortcuts import redirect, render
from django.contrib import messages
from django.contrib.auth.hashers import check_password
from django.views.decorators.cache import cache_control
from sdntoolswitch.models import Usermanagement
from sdntoolswitch.formvalidation import Validator
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.activitylogs import *
from sdntoolswitch.onosseclogs import *
from sdntoolswitch.aaalogs import *

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

def login(request):
    """
    View for login page
    """
    return render(request, "sdntool/index.html")


def logincontroller(request):
    """
    Controller for login page
    """
    global username
    global password
    username = request.POST.get("username")
    password = request.POST.get("password")
    with open("username.txt", "w") as file:
        file.write(username)

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
                    return redirect("configcontroller")
                else:
                    return redirect("home")

            else:
                messages.error(
                    request, "Your password is not correct", extra_tags="loginerror"
                )
                return redirect("login")
        else:
            messages.error(request, "User does not exists", extra_tags="loginerror")
            return redirect("login")


def logout(request):
    """
    Controller for logout
    """
    global username
    del request.session["login"]
    with open("iplist.txt", "w") as file:
        file.truncate()
    with open("portconf.json", "w") as file:
        file.truncate()
    with open("username.txt") as file:
        username = file.read()
    log_call(f"{username} logged out")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} logged out")
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
    with open("iplist.txt", "r") as file:
        ip = file.readlines()

    with open("username.txt") as file:
        username = file.read()
    log_call(f"{username} logged in")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} logged in")
    return render(request, "sdntool/home.html", {"ip": ip})