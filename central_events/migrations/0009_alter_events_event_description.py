# Generated by Django 4.2.2 on 2023-12-07 11:09

import ckeditor.fields
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('central_events', '0008_rename_super_event_name_events_super_event_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='events',
            name='event_description',
            field=ckeditor.fields.RichTextField(blank=True, null=True),
        ),
    ]
