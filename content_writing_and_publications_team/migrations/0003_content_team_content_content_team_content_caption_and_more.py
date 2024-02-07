# Generated by Django 4.2.2 on 2024-02-07 20:03

import ckeditor.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('content_writing_and_publications_team', '0002_alter_content_team_document_document'),
    ]

    operations = [
        migrations.CreateModel(
            name='Content_Team_Content',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=150)),
                ('description', ckeditor.fields.RichTextField(blank=True, null=True)),
                ('documents_link', models.URLField(blank=True, max_length=300, null=True)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'Content Team Content',
            },
        ),
        migrations.CreateModel(
            name='Content_Team_Content_Caption',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(blank=True, max_length=150, null=True)),
                ('caption', ckeditor.fields.RichTextField(blank=True, null=True)),
            ],
            options={
                'verbose_name': 'Content Team Content Caption',
            },
        ),
        migrations.CreateModel(
            name='Content_Team_Content_Document',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document', models.FileField(blank=True, null=True, upload_to='Content_Team_Documents/')),
            ],
            options={
                'verbose_name': 'Content Team Content Document',
            },
        ),
    ]
