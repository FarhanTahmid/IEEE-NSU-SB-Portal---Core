# Generated by Django 4.2.2 on 2023-12-29 20:50

import ckeditor.fields
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0029_rename_is_volunteer_roles_and_position_is_core_volunteer'),
    ]

    operations = [
        migrations.AddField(
            model_name='teams',
            name='team_short_description',
            field=ckeditor.fields.RichTextField(blank=True, max_length=200, null=True),
        ),
    ]
