# Generated by Django 4.2.2 on 2024-01-14 16:53

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('membership_development_team', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='portal_joining_requests',
            options={'ordering': ['position__rank'], 'verbose_name': 'Portal Joining Requests'},
        ),
    ]
