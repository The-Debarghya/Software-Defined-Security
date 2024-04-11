import logging
from django.shortcuts import redirect, render
from django.contrib.auth.hashers import make_password
from django.views.decorators.cache import cache_control
from sdntoolswitch.login_validator import login_check
from sdntoolswitch.models import Usermanagement, OnosServerManagement, NtpConfigRecords
from sdntoolswitch.generic_logger import logger_call

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
    role = request.POST.get("type")
    userdata = Usermanagement.objects.create(
        username=user, password=password, userrole=role
    )
    userdata.save()
    username = request.session["login"]["username"]

    msg = f"{username} created new {role} user {user}"
    logger_call(logging.INFO, msg, file_name="sds.log")
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
    msg = f"{username} deleted {userdata.userrole} user {userdata.username}"
    logger_call(logging.INFO, msg, file_name="sds.log")

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

    msg = f"{username} monitored user details"
    logger_call(logging.INFO, msg, file_name="sds.log")
    return render(request, "sdntool/showusers.html", {"userdata": userdata})