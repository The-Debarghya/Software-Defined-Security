from django.db import models


# Create your models here.
class Usermanagement(models.Model):
    idusermanagement = models.BigAutoField(primary_key=True)
    username = models.CharField(max_length=200)
    userrole = models.CharField(max_length=30)
    password = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    status=models.CharField(max_length=200,default='ACTIVE')

    class Meta:
        db_table = "usermanagement"