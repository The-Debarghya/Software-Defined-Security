# Generated by Django 5.0.3 on 2024-04-11 04:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sdntoolswitch', '0003_ntpconfigrecords_onosservermanagement'),
    ]

    operations = [
        migrations.AlterField(
            model_name='onosservermanagement',
            name='usercreated',
            field=models.CharField(max_length=200),
        ),
    ]
