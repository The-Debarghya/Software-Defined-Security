import syslog
from django.shortcuts import redirect, render
from django.contrib.auth.hashers import make_password
from django.views.decorators.cache import cache_control
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.models import Usermanagement, OnosServerManagement, NtpConfigRecords
from sdntoolswitch.activitylogs import *
from sdntoolswitch.onosseclogs import *
from sdntoolswitch.aaalogs import *

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

def createuserform(request):
    """
    View for creating user form
    """
    global username
    return render(request, "sdntool/Createuser.html")


@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def Createuser(request):
    """
    Controller for creating user
    """
    global username
    user = request.POST.get("U_id")
    password = make_password(request.POST.get("P_id"))
    type = request.POST.get("type")
    userdata = Usermanagement.objects.create(
        username=user, password=password, userrole=type
    )
    userdata.save()
    username = request.session["login"]["username"]

    log_call(f"{username} created new {type} user {user}")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} created new {type} user {user}")
    return redirect("showusers")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def deleteuser(request, id):
    """
    Controller for deleting user
    """
    global username
    userdata = Usermanagement.objects.get(idusermanagement=id)
    userdata.status = "INACTIVE"
    userdata.save()
    username = request.session["login"]["username"]
    OnosServerManagement.objects.filter(usercreated=userdata.username).delete()
    NtpConfigRecords.objects.filter(usercreated=userdata.username).delete()
    log_call(f"{username} deleted {userdata.userrole} user {userdata.username}")
    syslog.syslog(
        syslog.LOG_DEBUG,
        f"{username} deleted {userdata.userrole} user {userdata.username}",
    )

    return redirect("showusers")

@login_check
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def users(request):
    """
    View for users
    """
    global username
    userdata = Usermanagement.objects.filter(status="ACTIVE")
    username = request.session["login"]["username"]

    log_call(f"{username} monitored user details")
    syslog.syslog(syslog.LOG_DEBUG, f"{username} monitored user details")
    return render(request, "sdntool/showusers.html", {"userdata": userdata})