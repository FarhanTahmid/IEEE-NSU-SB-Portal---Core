# Generated by Django 4.0.5 on 2023-01-04 07:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0016_members_position'),
    ]

    operations = [
        migrations.AddField(
            model_name='members',
            name='user_profile_picture',
            field=models.ImageField(default='default_profile_picture.png', upload_to='user_profile_pictures/'),
        ),
    ]
