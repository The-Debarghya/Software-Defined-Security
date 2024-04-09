from datetime import datetime
import re

from django.shortcuts import redirect, render
from django.contrib import messages


def log(request):
    """
    View for SDS logs
    """
    if request.method == "POST":
        loglist = list()
        start = request.POST.get("startdate")
        start = datetime.strptime(start, "%Y-%m-%d").date()

        end = request.POST.get("enddate")
        end = datetime.strptime(end, "%Y-%m-%d").date()
        if start > end:
            messages.error(request, "start date should be less than end date")
            return redirect("date")

        with open("sds.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)

                # computed date
                # feeding format
                dt = datetime.strptime(match_str.group(), "%Y-%m-%d").date()

                f = file.split(" - ")
                if dt >= start and dt <= end:

                    loglist.append(
                        {
                            "status": f[-1],
                            "datetime": f[-3],
                            "date": str(dt),
                            "app": f[-4],
                        }
                    )
        loglist.reverse()
    else:

        loglist = list()
        with open("sds.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)

                f = file.split(" - ")

                loglist.append({"status": f[-1], "datetime": f[-3], "app": f[-4]})
        loglist.reverse()

    return render(request, "sdntool/log.html", {"logresponse": loglist})


def onosseclog(request):
    """
    View for ONOS security logs
    """
    if request.method == "POST":
        loglist = list()
        start = request.POST.get("startdate")
        start = datetime.strptime(start, "%Y-%m-%d").date()

        end = request.POST.get("enddate")
        end = datetime.strptime(end, "%Y-%m-%d").date()
        if start > end:
            messages.error(request, "start date should be less than end date")
            return redirect("date")

        with open("onossec.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)

                # computed date
                # feeding format
                dt = datetime.strptime(match_str.group(), "%Y-%m-%d").date()

                f = file.split(" - ")
                if dt >= start and dt <= end:

                    loglist.append(
                        {
                            "status": f[-1],
                            "datetime": f[-3],
                            "date": str(dt),
                            "app": f[-4],
                        }
                    )
        loglist.reverse()
    else:

        loglist = list()
        with open("onossec.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)

                f = file.split(" - ")

                loglist.append({"status": f[-1], "datetime": f[-3], "app": f[-4]})
        loglist.reverse()

    return render(request, "sdntool/onosseclog.html", {"logresponse": loglist})


def aaalog(request):
    """
    View for AAA logs
    """
    if request.method == "POST":
        loglist = list()
        start = request.POST.get("startdate")
        start = datetime.strptime(start, "%Y-%m-%d").date()

        end = request.POST.get("enddate")
        end = datetime.strptime(end, "%Y-%m-%d").date()
        if start > end:
            messages.error(request, "start date should be less than end date")
            return redirect("date")

        with open("aaa.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)
                dt = datetime.strptime(match_str.group(), "%Y-%m-%d").date()

                f = file.split(" - ")
                if dt >= start and dt <= end:

                    loglist.append(
                        {
                            "status": f[-1],
                            "datetime": f[-3],
                            "date": str(dt),
                            "app": f[-4],
                        }
                    )
        loglist.reverse()
    else:

        loglist = list()
        with open("aaa.log", "r") as logfile:
            for file in logfile:
                match_str = re.search(r"\d{4}-\d{2}-\d{2}", file)

                f = file.split(" - ")

                loglist.append({"status": f[-1], "datetime": f[-3], "app": f[-4]})
        loglist.reverse()

    return render(request, "sdntool/aaalogs.html", {"logresponse": loglist})


def aaadateform(request):
    """
    View for AAA logs date form
    """
    return render(request, "sdntool/aaadate.html")


def deleteaaalogconfirm(request):
    """
    View for deleting AAA logs
    """
    return render(request, "sdntool/deleteaaalogs.html")


def deleteaaalogs(request):
    """
    Controller for deleting AAA logs
    """
    with open("aaa.log", "w") as logfile:
        logfile.truncate()
    return redirect("aaalog")


def onossecdateform(request):
    """
    View for ONOS security logs date form
    """
    return render(request, "sdntool/onossecdate.html")


def dateform(request):
    """
    View for SDS logs date form
    """
    return render(request, "sdntool/date.html")


def deleteonosseclogconfirm(request):
    """
    View for deleting ONOS security logs
    """
    return render(request, "sdntool/deleteonosseclogs.html")


def deleteonosseclogs(request):
    """
    Controller for deleting ONOS security logs
    """
    with open("onossec.log", "w") as logfile:
        logfile.truncate()
    return redirect("onosseclog")


def deletelogs(request):

    with open("sds.log", "w") as logfile:
        logfile.truncate()
    return redirect("logmanagement")


def deletelogconfirm(request):
    return render(request, "sdntool/deletelogs.html")


def securitystats(request):
    return render(request, "sdntool/securitystats.html")