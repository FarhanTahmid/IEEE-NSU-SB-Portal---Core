# Generated by Django 4.2.2 on 2024-01-06 15:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main_website', '0012_merge_20240106_2057'),
    ]

    operations = [
        migrations.AlterField(
            model_name='galleryvideos',
            name='video_link',
            field=models.URLField(help_text='Please use embed link if you are pasting a link of Youtube video!'),
        ),
    ]
