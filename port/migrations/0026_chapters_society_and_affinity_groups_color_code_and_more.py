# Generated by Django 4.2.2 on 2023-12-07 19:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0025_roles_and_position_is_mentor'),
    ]

    operations = [
        migrations.AddField(
            model_name='chapters_society_and_affinity_groups',
            name='color_code',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='chapters_society_and_affinity_groups',
            name='logo',
            field=models.ImageField(blank=True, null=True, upload_to='sc_ag_logos/'),
        ),
        migrations.AddField(
            model_name='chapters_society_and_affinity_groups',
            name='short_form',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
    ]
