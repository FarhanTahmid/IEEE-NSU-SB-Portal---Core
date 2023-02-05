# Generated by Django 3.2.16 on 2023-02-01 17:35

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('membership_development_team', '0017_renewal_form_info_form_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='renewal_form_info',
            name='id',
        ),
        migrations.AddField(
            model_name='renewal_form_info',
            name='session',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='membership_development_team.renewal_sessions'),
        ),
        migrations.AlterField(
            model_name='renewal_form_info',
            name='form_id',
            field=models.IntegerField(default=0, primary_key=True, serialize=False),
        ),
    ]
