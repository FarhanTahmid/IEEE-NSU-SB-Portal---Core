# Generated by Django 4.1.2 on 2022-12-01 20:14

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('recruitment', '0011_alter_recruited_members_recruitment_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='recruited_members',
            name='recruitment_time',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2022, 12, 2, 2, 14, 17, 813187), null=True),
        ),
    ]
