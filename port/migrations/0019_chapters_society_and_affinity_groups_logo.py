# Generated by Django 4.2.2 on 2024-01-13 04:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0018_remove_chapters_society_and_affinity_groups_logo'),
    ]

    operations = [
        migrations.AddField(
            model_name='chapters_society_and_affinity_groups',
            name='logo',
            field=models.ImageField(blank=True, null=True, upload_to='sc_ag_logos/'),
        ),
    ]
