# Generated by Django 4.2.2 on 2023-10-29 13:12

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0020_panels'),
        ('users', '0043_remove_executive_commitee_members_ex_member_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='members',
            name='panel_session',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='port.panels'),
        ),
    ]
