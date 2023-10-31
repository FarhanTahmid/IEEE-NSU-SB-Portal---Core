# Generated by Django 4.2.2 on 2023-10-31 19:57

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0047_alter_panel_members_options'),
        ('system_administration', '0027_system'),
    ]

    operations = [
        migrations.CreateModel(
            name='Branch_Data_Access',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('create_event_access', models.BooleanField(default=False)),
                ('event_details_page_access', models.BooleanField(default=False)),
                ('create_panels_access', models.BooleanField(default=False)),
                ('panel_memeber_add_remove_access', models.BooleanField(default=False)),
                ('team_details_page', models.BooleanField(default=False)),
                ('manage_web_access', models.BooleanField(default=False)),
                ('manage_web_home_access', models.BooleanField(default=False)),
                ('ieee_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.members')),
            ],
            options={
                'verbose_name': 'Branch Data Access',
            },
        ),
    ]
