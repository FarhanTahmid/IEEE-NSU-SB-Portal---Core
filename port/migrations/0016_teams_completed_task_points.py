# Generated by Django 4.2.2 on 2024-05-13 05:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0015_skillsettypes'),
    ]

    operations = [
        migrations.AddField(
            model_name='teams',
            name='completed_task_points',
            field=models.FloatField(default=0),
        ),
    ]
