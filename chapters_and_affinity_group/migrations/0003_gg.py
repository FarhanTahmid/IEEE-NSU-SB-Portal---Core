# Generated by Django 4.2.2 on 2023-12-05 19:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chapters_and_affinity_group', '0002_alter_sc_ag_members_position_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='GG',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
            ],
            options={
                'verbose_name': 'uhbedf',
            },
        ),
    ]
