# Generated by Django 4.2.2 on 2023-08-04 06:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0008_roles_and_position_id2'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='roles_and_position',
            name='id2',
        ),
        migrations.AlterField(
            model_name='roles_and_position',
            name='id',
            field=models.IntegerField(default=0, primary_key=True, serialize=False),
        ),
    ]
