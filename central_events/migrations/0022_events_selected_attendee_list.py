# Generated by Django 4.2.2 on 2024-07-13 21:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('central_events', '0021_events_additional_attendees'),
    ]

    operations = [
        migrations.AddField(
            model_name='events',
            name='selected_attendee_list',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
