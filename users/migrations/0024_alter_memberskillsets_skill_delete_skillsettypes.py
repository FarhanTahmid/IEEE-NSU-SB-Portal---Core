# Generated by Django 4.2.2 on 2024-02-28 16:02

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0015_skillsettypes'),
        ('users', '0023_skillsettypes_memberskillsets'),
    ]

    operations = [
        migrations.AlterField(
            model_name='memberskillsets',
            name='skill',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='port.skillsettypes'),
        ),
        migrations.DeleteModel(
            name='SkillSetTypes',
        ),
    ]
