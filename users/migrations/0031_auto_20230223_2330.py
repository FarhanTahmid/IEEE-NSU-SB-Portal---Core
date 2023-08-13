# Generated by Django 3.2.16 on 2023-02-23 17:30

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('membership_development_team', '0019_alter_renewal_form_info_further_contact_member_id'),
        ('users', '0030_members_last_renewal_session2'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='members',
            name='last_renewal_session2',
        ),
        migrations.RemoveField(
            model_name='members',
            name='last_renewal_time',
        ),
        migrations.AlterField(
            model_name='members',
            name='last_renewal_session',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='membership_development_team.renewal_sessions'),
        ),
    ]
