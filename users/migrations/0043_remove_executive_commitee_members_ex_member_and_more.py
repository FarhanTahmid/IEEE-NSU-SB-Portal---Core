# Generated by Django 4.2.2 on 2023-10-29 08:34

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0042_alter_user_options'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='executive_commitee_members',
            name='ex_member',
        ),
        migrations.RemoveField(
            model_name='executive_commitee_members',
            name='member',
        ),
        migrations.RemoveField(
            model_name='executive_commitee_members',
            name='position',
        ),
        migrations.RemoveField(
            model_name='executive_commitee_members',
            name='year',
        ),
        migrations.DeleteModel(
            name='Executive_commitee',
        ),
        migrations.DeleteModel(
            name='Executive_commitee_members',
        ),
    ]
