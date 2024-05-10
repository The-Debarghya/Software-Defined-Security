from functools import wraps

from django.shortcuts import redirect


def admin_check(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        if request.session.get("login"):
            if request.session["login"]["userrole"] == "admin":
                return function(request, *args, **kwargs)
            else:
                return redirect("home")
        else:
            return redirect("login")

    return wrap


def admin_manager_check(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        if request.session.get("login"):
            if (
                request.session["login"]["userrole"] == "admin"
                or request.session["login"]["userrole"] == "manager"
            ):
                return function(request, *args, **kwargs)
            else:
                return redirect("home")
        else:
            return redirect("login")

    return wrap
