# Generated by Django 4.2.2 on 2024-02-27 05:32

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('task_assignation', '0011_task_log_alter_task_start_date_delete_task_history_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='task_log',
            options={'verbose_name': 'Task Log'},
        ),
    ]
