# Generated by Django 4.2.2 on 2024-01-14 22:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('recruitment', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='recruited_members',
            name='unique_code',
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
    ]
