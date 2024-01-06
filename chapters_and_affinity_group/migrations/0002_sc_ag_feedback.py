# Generated by Django 4.2.2 on 2024-01-06 12:23

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('port', '0015_chapters_society_and_affinity_groups_secondary_color_code_and_more'),
        ('chapters_and_affinity_group', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='SC_AG_FeedBack',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateField(auto_now_add=True)),
                ('name', models.CharField(max_length=100)),
                ('email', models.EmailField(blank=True, max_length=254, null=True)),
                ('message', models.TextField(blank=True, null=True)),
                ('is_responded', models.BooleanField(default=False)),
                ('society', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='port.chapters_society_and_affinity_groups')),
            ],
            options={
                'verbose_name': 'FeedBacks',
            },
        ),
    ]
