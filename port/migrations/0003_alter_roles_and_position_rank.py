# Generated by Django 4.2.2 on 2024-01-14 12:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0002_roles_and_position_rank'),
    ]

    operations = [
        migrations.AlterField(
            model_name='roles_and_position',
            name='rank',
            field=models.IntegerField(blank=True, default=5000, null=True),
        ),
    ]
