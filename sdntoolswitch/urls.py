from django.urls import path
from sdntoolswitch import views

urlpatterns = [
    # login functions
    path("", views.login, name="login"),
    path("logincontroller/", views.logincontroller, name="logincontroller"),
    path("logout/", views.logout, name="logout"),
    path("dashboard/", views.home, name="home"),
    # AAA functions
    path("AAA/", views.aaa, name="AAA"),
    path("aaacontroller/", views.aaacontroller, name="aaacontroller"),
    path("viewradius/", views.viewradius, name="viewradius"),
    # DDOS and NTP functions
    path("ddos/", views.ddos, name="DDOS"),
    path("ntp/", views.ntp, name="ntp"),
    path("disablentp/", views.disablentp, name="disablentp"),
    path("configntp/", views.configntp, name="configntp"),
    # User functions
    path("CREATEUSER/", views.Createuser, name="CREATE_USER"),
    path("showusers/", views.users, name="showusers"),
    path("createuserform/", views.createuserform, name="createuserform"),
    path("deleteuser/<int:id>", views.deleteuser, name="deleteuser"),
    # Config password functions
    path("addconfig/", views.addconfig, name="configcontroller"),
    path("extraconfig/", views.addextraconfig, name="extraconfig"),
    path("addpassword/", views.addconfigpassword, name="addconfigpasswordcontroller"),
    path("modifypassword/", views.modifypassword, name="modifypassword"),
    path("disablepassword/", views.disablepassword, name="disablepassword"),
    path(
        "passwordisable/", views.disablepasswordconfirm, name="disablepasswordconfirm"
    ),
    path(
        "viewpasswordconfiguration/",
        views.viewpasswordconfiguration,
        name="viewconfigurationpassword",
    ),
    # https functions
    path("modifyhttp/", views.modifyhttp, name="modifyhttp"),
    path("disablehttp/", views.disablehttp, name="disablehttp"),
    path("httpdisable/", views.disablehttpconfirm, name="httpdisableconfirm"),
    path("viewhttp/", views.viewhttp, name="viewhttp"),
    # tls functions
    path("modifytls/", views.modifytls, name="modifytls"),
    path("disabletls/", views.disabletls, name="disabletls"),
    path("viewtls/", views.viewtls, name="viewtls"),
    path("tlsdisable/", views.disabletlsconfirm, name="disabletlsconfirm"),
    # firewall functions
    path("addfire/", views.addfire, name="addfire"),
    path("addfirecontroller/", views.addfirecontroller, name="addfirecontroller"),
    path("viewrules/", views.viewrules, name="viewrules"),
    path("deleterules/<str:id>", views.deleterules, name="deleterules"),
    path("addrulesbyport/", views.addrulesbyport, name="addrulesbyport"),
    path(
        "addrulesbyportcontroller/",
        views.addrulesbyportcontroller,
        name="addrulesbyportcontroller",
    ),
    path("addrulesbysrc/", views.addrulesbysrc, name="addrulesbysrc"),
    path(
        "addrulesbysrccontroller/",
        views.addrulesbysrccontroller,
        name="addrulesbysrccontroller",
    ),
    # log functions
    path("log/", views.log, name="logmanagement"),
    path("date/", views.dateform, name="date"),
    path("deletelogs/", views.deletelogs, name="deletelogs"),
    path("deletelogconfirm/", views.deletelogconfirm, name="deletelogconfirm"),
    path(
        "deleteonosseclogconfirm/",
        views.deleteonosseclogconfirm,
        name="deleteonosseclogconfirm",
    ),
    path("deleteonosseclogs/", views.deleteonosseclogs, name="deleteonosseclogs"),
    path("onosseclog/", views.onosseclog, name="onosseclog"),
    path("onossecdateform/", views.onossecdateform, name="onossecdateform"),
]
