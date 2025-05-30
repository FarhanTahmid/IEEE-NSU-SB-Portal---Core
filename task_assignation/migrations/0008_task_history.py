# Generated by Django 4.2.2 on 2024-02-25 05:24

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('task_assignation', '0007_rename_has_picture_upload_task_has_media'),
    ]

    operations = [
        migrations.CreateModel(
            name='Task_History',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('task_history', models.TextField(blank=True, default=None, null=True)),
                ('task_number', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='task_assignation.task')),
            ],
            options={
                'verbose_name': 'Task History',
            },
        ),
    ]
