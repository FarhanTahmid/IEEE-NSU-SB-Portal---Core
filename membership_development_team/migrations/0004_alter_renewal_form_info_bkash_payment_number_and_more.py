# Generated by Django 4.2.2 on 2024-11-06 15:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('membership_development_team', '0003_birthday_email_records'),
    ]

    operations = [
        migrations.AlterField(
            model_name='renewal_form_info',
            name='bkash_payment_number',
            field=models.CharField(blank=True, max_length=45, null=True),
        ),
        migrations.AlterField(
            model_name='renewal_form_info',
            name='nagad_payment_number',
            field=models.CharField(blank=True, max_length=45, null=True),
        ),
    ]
