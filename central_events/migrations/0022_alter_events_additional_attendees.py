# Generated by Django 4.2.2 on 2024-07-12 15:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('central_events', '0021_events_additional_attendees'),
    ]

    operations = [
        migrations.AlterField(
            model_name='events',
            name='additional_attendees',
            field=models.JSONField(blank=True, default=dict, null=True),
        ),
    ]
