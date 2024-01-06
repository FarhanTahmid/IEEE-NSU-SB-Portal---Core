# Generated by Django 4.2.2 on 2024-01-05 19:09

from django.db import migrations
import django_resized.forms


class Migration(migrations.Migration):

    dependencies = [
        ('main_website', '0006_about_ieee'),
    ]

    operations = [
        migrations.AlterField(
            model_name='about_ieee',
            name='about_image',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE/'),
        ),
        migrations.AlterField(
            model_name='about_ieee',
            name='community_image',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE/'),
        ),
        migrations.AlterField(
            model_name='about_ieee',
            name='innovations_and_developments_image',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE/'),
        ),
        migrations.AlterField(
            model_name='about_ieee',
            name='quality_image',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE/'),
        ),
        migrations.AlterField(
            model_name='about_ieee',
            name='students_and_member_activities_image',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE/'),
        ),
        migrations.AlterField(
            model_name='ieee_bangladesh_section',
            name='ieee_bangladesh_logo',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE Bangladesh Section/logo/'),
        ),
        migrations.AlterField(
            model_name='ieee_bangladesh_section',
            name='member_and_volunteer_picture',
            field=django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE Bangladesh Section/member_volunteer_picture/'),
        ),
    ]
