# Generated by Django 4.2.2 on 2024-01-14 07:26

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Email_Attachements',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email_name', models.CharField(blank=True, max_length=1000, null=True)),
                ('email_content', models.FileField(blank=True, default=None, null=True, upload_to='Email Attachments/')),
            ],
            options={
                'verbose_name': 'Email Attachments',
            },
        ),
        migrations.CreateModel(
            name='Manage_Team',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('manage_team_access', models.BooleanField(default=False, verbose_name='Team Access')),
                ('manage_email_access', models.BooleanField(default=False, verbose_name='Email Access')),
                ('ieee_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.members', verbose_name='IEEE ID')),
            ],
            options={
                'verbose_name': 'Manage Team Access',
            },
        ),
    ]
