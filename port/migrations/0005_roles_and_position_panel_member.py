# Generated by Django 4.2.2 on 2023-07-15 08:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0004_alter_chapters_society_and_affinity_groups_options_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='roles_and_position',
            name='panel_member',
            field=models.BooleanField(default=False),
        ),
    ]
