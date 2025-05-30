# Generated by Django 4.2.2 on 2024-05-10 07:10

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0015_skillsettypes'),
        ('task_assignation', '0026_member_task_upload_types_is_task_started_by_member'),
    ]

    operations = [
        migrations.CreateModel(
            name='Team_Task_Forwarded',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('task_forwarded_to_incharge', models.BooleanField(default=False)),
                ('forwared_by', models.CharField(default='', max_length=15)),
                ('task', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='task_assignation.task')),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='port.teams')),
            ],
            options={
                'verbose_name': 'Team Task Forward',
            },
        ),
    ]
