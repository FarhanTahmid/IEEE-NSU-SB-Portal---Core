# Generated by Django 4.2.2 on 2024-07-09 15:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('notification', '0006_notifications_title'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notifications',
            name='general_message',
            field=models.CharField(blank=True, max_length=3000, null=True),
        ),
    ]
