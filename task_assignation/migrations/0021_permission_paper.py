# Generated by Django 4.2.2 on 2024-03-09 15:11

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('task_assignation', '0020_alter_task_options'),
    ]

    operations = [
        migrations.CreateModel(
            name='Permission_Paper',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('permission_paper', models.CharField(default='', max_length=50)),
                ('task', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='task_assignation.task')),
            ],
        ),
    ]
