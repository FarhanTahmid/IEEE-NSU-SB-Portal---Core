# Generated by Django 4.2.2 on 2024-02-17 12:46

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('central_events', '0008_alter_events_event_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='events',
            name='event_date',
            field=models.DateField(blank=True, default=datetime.datetime(2024, 2, 17, 12, 46, 56, 611881, tzinfo=datetime.timezone.utc), null=True),
        ),
    ]
