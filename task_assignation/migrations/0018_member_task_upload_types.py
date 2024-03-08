# Generated by Django 4.2.2 on 2024-03-08 07:00

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0029_alter_members_completed_task_points'),
        ('task_assignation', '0017_alter_member_task_point_completion_points_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Member_Task_Upload_Types',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('has_drive_link', models.BooleanField(default=False)),
                ('has_file_upload', models.BooleanField(default=False)),
                ('has_content', models.BooleanField(default=False)),
                ('has_media', models.BooleanField(default=False)),
                ('has_permission_paper', models.BooleanField(default=False)),
                ('task_member', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.members')),
            ],
            options={
                'verbose_name': 'Member Task Upload Types',
            },
        ),
    ]
