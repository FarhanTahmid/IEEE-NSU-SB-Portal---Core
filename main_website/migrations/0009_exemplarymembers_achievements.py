# Generated by Django 4.2.2 on 2024-01-06 06:54

import ckeditor.fields
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('main_website', '0008_exemplarymembers_alter_blog_description_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='exemplarymembers',
            name='achievements',
            field=ckeditor.fields.RichTextField(blank=True, max_length=1000, null=True),
        ),
    ]
