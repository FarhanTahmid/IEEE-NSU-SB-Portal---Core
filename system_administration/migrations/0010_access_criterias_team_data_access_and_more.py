# Generated by Django 4.0.5 on 2022-12-31 17:56

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0002_roles_and_position'),
        ('users', '0016_members_position'),
        ('system_administration', '0009_mdt_data_access_remove_team_data_access_criteria_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Access_Criterias',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('criteria_name', models.CharField(default='all', max_length=30)),
                ('team', models.ForeignKey(default=13, on_delete=django.db.models.deletion.CASCADE, to='port.teams')),
            ],
            options={
                'verbose_name': 'Data Access Criteria',
            },
        ),
        migrations.CreateModel(
            name='Team_Data_Access',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('has_permission', models.BooleanField(default=False, verbose_name='Permission Status')),
                ('criteria', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='system_administration.access_criterias', verbose_name='Accepted Permission Criteria')),
                ('ieee_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.members', verbose_name='IEEE ID')),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='port.teams', verbose_name='Team')),
            ],
            options={
                'verbose_name': 'Team Data Access',
            },
        ),
        migrations.DeleteModel(
            name='MDT_Data_Access',
        ),
    ]
