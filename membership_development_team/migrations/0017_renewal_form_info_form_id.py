# Generated by Django 3.2.16 on 2023-02-01 16:23

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('membership_development_team', '0016_auto_20230131_2321'),
    ]

    operations = [
        migrations.AddField(
            model_name='renewal_form_info',
            name='form_id',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='membership_development_team.renewal_sessions'),
        ),
    ]
