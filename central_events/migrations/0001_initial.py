# Generated by Django 4.2.2 on 2023-12-05 19:15

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Event_Categories',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_category', models.CharField(max_length=60)),
            ],
            options={
                'verbose_name': 'Event Category',
            },
        ),
    ]
