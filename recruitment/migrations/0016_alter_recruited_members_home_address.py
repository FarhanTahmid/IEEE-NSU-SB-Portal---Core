# Generated by Django 4.0.5 on 2022-12-31 06:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('recruitment', '0015_alter_recruited_members_recruitment_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='recruited_members',
            name='home_address',
            field=models.CharField(blank=True, max_length=300, null=True),
        ),
    ]
