from django.contrib import admin
from .models import Usermanagement, OnosServerManagement, NtpConfigRecords

# Register your models here.
admin.site.register(Usermanagement)
admin.site.register(OnosServerManagement)
admin.site.register(NtpConfigRecords)
