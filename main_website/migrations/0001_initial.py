# Generated by Django 4.2.2 on 2024-01-06 15:43

import ckeditor.fields
from django.db import migrations, models
import django.db.models.deletion
import django_resized.forms


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('port', '0015_chapters_society_and_affinity_groups_secondary_color_code_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='About_IEEE',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('about_ieee', models.TextField(blank=True, null=True)),
                ('about_image', django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE/About Image/')),
                ('community_description', models.TextField(blank=True, null=True)),
                ('community_image', django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE/Community Image/')),
                ('start_with_ieee_description', models.TextField(blank=True, null=True)),
                ('collaboration_description', models.TextField(blank=True, null=True)),
                ('publications_description', models.TextField(blank=True, null=True)),
                ('events_and_conferences_description', models.TextField(blank=True, null=True)),
                ('achievements_description', models.TextField(blank=True, null=True)),
                ('innovations_and_developments_description', models.TextField(blank=True, null=True)),
                ('innovations_and_developments_image', django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE/Innovation Development Image/')),
                ('students_and_member_activities_description', models.TextField(blank=True, null=True)),
                ('students_and_member_activities_image', django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE/Student Member Activity Image/')),
                ('quality_description', models.TextField(blank=True, null=True)),
                ('quality_image', django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE/Quality Image/')),
            ],
            options={
                'verbose_name': 'About IEEE',
            },
        ),
        migrations.CreateModel(
            name='BannerPictureWithStat',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', django_resized.forms.ResizedImageField(crop=None, force_format='JPEG', keep_meta=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/homepage/ribbon_picture')),
            ],
            options={
                'verbose_name': 'Banner Picture with Statistics in Homepage',
            },
        ),
        migrations.CreateModel(
            name='Blog_Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('blog_category', models.CharField(max_length=40)),
            ],
        ),
        migrations.CreateModel(
            name='ExemplaryMembers',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('member_name', models.CharField(max_length=100)),
                ('member_picture', models.ImageField(blank=True, null=True, upload_to='main_website_files/exemplary_members_picture/')),
                ('former_position', models.CharField(blank=True, max_length=100, null=True)),
                ('activity_year', models.CharField(blank=True, max_length=50, null=True)),
                ('current_activity', models.CharField(blank=True, max_length=200, null=True)),
                ('facebook_account_link', models.URLField(blank=True, null=True)),
                ('email', models.EmailField(blank=True, max_length=254, null=True)),
                ('achievements', ckeditor.fields.RichTextField(blank=True, max_length=1000, null=True)),
                ('rank', models.IntegerField(blank=True, help_text='This is used to sort exemplary members in the main website', null=True)),
            ],
            options={
                'verbose_name': 'Exemplary Members',
            },
        ),
        migrations.CreateModel(
            name='GalleryImages',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', django_resized.forms.ResizedImageField(crop=None, force_format='JPEG', keep_meta=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/gallery_pictures/')),
                ('upload_date', models.DateField()),
            ],
            options={
                'verbose_name': 'Gallery Image',
            },
        ),
        migrations.CreateModel(
            name='HomePage_Thoughts',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quote', models.TextField()),
                ('author', models.CharField(max_length=500)),
            ],
            options={
                'verbose_name': 'HomePage Thoughts',
            },
        ),
        migrations.CreateModel(
            name='HomePageTopBanner',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('banner_picture', django_resized.forms.ResizedImageField(crop=None, force_format='JPEG', keep_meta=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/homepage/banner_pictures')),
                ('first_layer_text', models.CharField(default='FOCUSING LIMELIGHT ON', max_length=50)),
                ('first_layer_text_colored', models.CharField(default='MASTERMINDS', max_length=20)),
                ('third_layer_text', models.TextField(max_length=200)),
                ('button_text', models.CharField(default='About INSB', max_length=50)),
                ('button_url', models.CharField(default='#', max_length=200)),
            ],
            options={
                'verbose_name': 'Homepage Banner Picture With Texts',
            },
        ),
        migrations.CreateModel(
            name='IEEE_Bangladesh_Section',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('about_ieee_bangladesh', models.TextField(blank=True, null=True)),
                ('ieee_bangladesh_logo', django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE Bangladesh Section/logo/')),
                ('member_and_volunteer_description', models.TextField(blank=True, null=True)),
                ('member_and_volunteer_picture', django_resized.forms.ResizedImageField(blank=True, crop=None, force_format='JPEG', keep_meta=True, null=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE Bangladesh Section/member_volunteer_picture/')),
                ('benefits_description', models.TextField(blank=True, null=True)),
                ('student_branches_description', models.TextField(blank=True, null=True)),
                ('affinity_groups_description', models.TextField(blank=True, null=True)),
                ('community_and_society_description', models.TextField(blank=True, null=True)),
            ],
            options={
                'verbose_name': 'IEEE Bangladesh Section',
            },
        ),
        migrations.CreateModel(
            name='IEEE_Bangladesh_Section_Gallery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('picture', django_resized.forms.ResizedImageField(crop=None, force_format='JPEG', keep_meta=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/About/IEEE Bangladesh Section/Gallery/')),
            ],
            options={
                'verbose_name': 'IEEE Bangladesh Section Gallery',
            },
        ),
        migrations.CreateModel(
            name='News',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('news_title', models.CharField(max_length=150)),
                ('news_subtitle', models.CharField(blank=True, max_length=100, null=True)),
                ('news_description', ckeditor.fields.RichTextField(max_length=500)),
                ('news_picture', models.ImageField(upload_to='main_website_files/news/')),
                ('news_date', models.DateField(blank=True, help_text='Please use the following format: <em>YYYY-MM-DD</em>.', null=True)),
            ],
            options={
                'verbose_name': 'News',
            },
        ),
        migrations.CreateModel(
            name='ResearchCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('category', models.CharField(max_length=100)),
            ],
            options={
                'verbose_name': 'Research Category',
            },
        ),
        migrations.CreateModel(
            name='Research_Papers',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('research_banner_picture', models.ImageField(default='main_website_files/Research_pictures/default_research_banner_picture.png', upload_to='main_website_files/Research_pictures/')),
                ('author_names', ckeditor.fields.RichTextField(max_length=300)),
                ('short_description', ckeditor.fields.RichTextField(max_length=500)),
                ('publish_date', models.DateField(help_text='<br>Please use the following format: <em>YYYY-MM-DD</em>.')),
                ('publication_link', models.URLField()),
                ('publish_research', models.BooleanField(default=False)),
                ('category', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='main_website.researchcategory')),
            ],
            options={
                'verbose_name': 'Research Paper',
            },
        ),
        migrations.CreateModel(
            name='Magazines',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('magazine_title', models.CharField(max_length=100)),
                ('publish_date', models.DateField(help_text='<br>Please use the following format: <em>YYYY-MM-DD</em>.')),
                ('magazine_short_description', ckeditor.fields.RichTextField(max_length=400)),
                ('magazine_picture', django_resized.forms.ResizedImageField(crop=None, force_format='JPEG', keep_meta=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/magazine_pictures/')),
                ('magazine_file', models.FileField(upload_to='main_website_files/Magazine/')),
                ('published_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='port.chapters_society_and_affinity_groups')),
            ],
            options={
                'verbose_name': 'Magazine',
            },
        ),
        migrations.CreateModel(
            name='Blog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('writer_name', models.CharField(max_length=50)),
                ('title', models.CharField(max_length=150)),
                ('date', models.DateField(help_text='<br>Please use the following format: <em>YYYY-MM-DD</em>.')),
                ('short_description', ckeditor.fields.RichTextField(help_text='Write within 50 words!', max_length=200)),
                ('blog_banner_picture', django_resized.forms.ResizedImageField(crop=None, default='main_website_files/Blog_banner_pictures/default_blog_banner_picture.png', force_format='JPEG', keep_meta=True, quality=80, scale=1.0, size=[1920, 1080], upload_to='main_website_files/Blog_pictures/')),
                ('description', ckeditor.fields.RichTextField(help_text='Write within 500 words!', max_length=5000)),
                ('publish_blog', models.BooleanField(default=False)),
                ('branch_or_society', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='port.chapters_society_and_affinity_groups')),
                ('category', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='main_website.blog_category')),
            ],
            options={
                'verbose_name': 'Blog',
            },
        ),
        migrations.CreateModel(
            name='Achievements',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('award_name', models.CharField(max_length=100)),
                ('award_description', ckeditor.fields.RichTextField(blank=True, max_length=1000, null=True)),
                ('award_winning_year', models.IntegerField()),
                ('award_picture', models.ImageField(upload_to='main_website_files/achievements/')),
                ('award_of', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='port.chapters_society_and_affinity_groups')),
            ],
            options={
                'verbose_name': 'Achievements',
            },
        ),
    ]
