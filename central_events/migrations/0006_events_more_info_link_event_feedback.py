# Generated by Django 4.2.2 on 2024-01-12 14:55

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('central_events', '0005_alter_events_event_time'),
    ]

    operations = [
        migrations.AddField(
            model_name='events',
            name='more_info_link',
            field=models.URLField(blank=True, max_length=500, null=True),
        ),
        migrations.CreateModel(
            name='Event_Feedback',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateField(auto_now_add=True)),
                ('name', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('satisfaction', models.CharField(max_length=50)),
                ('comment', models.TextField(max_length=400)),
                ('event_organiser', models.ForeignKey(default=5, on_delete=django.db.models.deletion.CASCADE, to='port.chapters_society_and_affinity_groups')),
            ],
            options={
                'verbose_name': 'Event Feedback',
            },
        ),
    ]
