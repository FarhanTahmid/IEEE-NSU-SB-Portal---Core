# Generated by Django 4.2.2 on 2024-06-26 21:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('central_events', '0015_alter_events_registration_fee_amount'),
    ]

    operations = [
        migrations.AddField(
            model_name='events',
            name='google_calendar_event_id',
            field=models.CharField(blank=True, null=True),
        ),
    ]
