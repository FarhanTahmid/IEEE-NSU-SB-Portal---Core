# Generated by Django 4.2.2 on 2024-01-03 11:25

import ckeditor.fields
from django.db import migrations, models
import django_resized.forms


class Migration(migrations.Migration):

    dependencies = [
        ('main_website', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='IEEE_Bangladesh_Section',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('about_ieee_bangladesh', ckeditor.fields.RichTextField(blank=True, null=True)),
                ('ieee_bangladesh_logo', django_resized.forms.ResizedImageField(crop=None, force_format='JPEG', keep_meta=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE Bangladesh Section/logo/')),
                ('member_and_volunteer_picture', django_resized.forms.ResizedImageField(crop=None, force_format='JPEG', keep_meta=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE Bangladesh Section/member_volunteer_picture/')),
            ],
        ),
        migrations.CreateModel(
            name='IEEE_Bangladesh_Section_Gallery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('picture', django_resized.forms.ResizedImageField(crop=None, force_format='JPEG', keep_meta=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE Bangladesh Section/Gallery/')),
            ],
            options={
                'verbose_name': 'IEEE BD Section Gallery',
            },
        ),
    ]
