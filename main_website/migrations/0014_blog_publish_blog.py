# Generated by Django 4.2.2 on 2023-12-18 06:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main_website', '0013_rename_chapter_society_affinity_blog_branch_or_society_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='blog',
            name='publish_blog',
            field=models.BooleanField(default=False),
        ),
    ]
