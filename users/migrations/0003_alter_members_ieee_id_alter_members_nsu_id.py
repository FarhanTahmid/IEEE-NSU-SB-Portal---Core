# Generated by Django 4.1.2 on 2022-11-03 06:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_rename_iee_id_members_ieee_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='members',
            name='ieee_id',
            field=models.CharField(max_length=20, primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='members',
            name='nsu_id',
            field=models.CharField(max_length=20),
        ),
    ]
