# Generated by Django 4.2.2 on 2023-08-14 11:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0011_alter_roles_and_position_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='teams',
            name='primary',
            field=models.IntegerField(default=0),
        ),
    ]
