# Generated by Django 4.2.2 on 2024-01-14 22:11

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0003_alter_roles_and_position_rank'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='roles_and_position',
            options={'ordering': ['rank'], 'verbose_name': 'Registered positions'},
        ),
    ]
