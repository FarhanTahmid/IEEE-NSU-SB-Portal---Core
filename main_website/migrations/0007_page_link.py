# Generated by Django 4.2.2 on 2024-01-07 22:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main_website', '0006_alter_blog_is_requested'),
    ]

    operations = [
        migrations.CreateModel(
            name='Page_Link',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('page_title', models.CharField(max_length=120)),
                ('category', models.CharField(max_length=120)),
                ('title', models.CharField(max_length=120)),
                ('link', models.URLField(max_length=250)),
            ],
            options={
                'verbose_name': 'Page Link',
            },
        ),
    ]
