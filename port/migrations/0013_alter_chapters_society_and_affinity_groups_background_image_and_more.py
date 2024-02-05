# Generated by Django 4.2.2 on 2024-01-18 04:51

from django.db import migrations
import django_resized.forms


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0012_alter_chapters_society_and_affinity_groups_background_image_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='chapters_society_and_affinity_groups',
            name='background_image',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, force_format=None, keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/societies_&_ag/background_image/', verbose_name='Background Image'),
        ),
        migrations.AlterField(
            model_name='chapters_society_and_affinity_groups',
            name='mission_picture',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, force_format=None, keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/societies_&_ag/mission_picture/', verbose_name='Mission Image'),
        ),
        migrations.AlterField(
            model_name='chapters_society_and_affinity_groups',
            name='vision_picture',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, force_format=None, keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/societies_&_ag/vision_picture/', verbose_name='Vision Image'),
        ),
    ]
