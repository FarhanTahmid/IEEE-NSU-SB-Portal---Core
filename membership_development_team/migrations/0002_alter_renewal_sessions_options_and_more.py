# Generated by Django 4.1.2 on 2022-12-09 17:08

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('membership_development_team', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='renewal_sessions',
            options={'verbose_name': 'Renewal Session'},
        ),
        migrations.RenameField(
            model_name='renewal_requests',
            old_name='session_name',
            new_name='session_id',
        ),
    ]
