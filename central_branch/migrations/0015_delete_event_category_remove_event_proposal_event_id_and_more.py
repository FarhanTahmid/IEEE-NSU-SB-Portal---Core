# Generated by Django 4.2.2 on 2023-12-05 21:36

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('central_events', '0003_events_rename_event_categories_event_category_and_more'),
        ('central_branch', '0014_event_category_remove_events_type_of_event_and_more'),
    ]

    operations = [
        # migrations.DeleteModel(
        #     name='Event_Category',
        # ),
        # migrations.RemoveField(
        #     model_name='event_proposal',
        #     name='event_id',
        # ),
        # migrations.RemoveField(
        #     model_name='event_venue',
        #     name='event_id',
        # ),
        # migrations.RemoveField(
        #     model_name='event_venue',
        #     name='venue_id',
        # ),
        # migrations.RemoveField(
        #     model_name='events',
        #     name='event_organiser',
        # ),
        # migrations.RemoveField(
        #     model_name='events',
        #     name='super_event_name',
        # ),
        # migrations.RemoveField(
        #     model_name='interbranchcollaborations',
        #     name='collaboration_with',
        # ),
        # migrations.RemoveField(
        #     model_name='interbranchcollaborations',
        #     name='event_id',
        # ),
        # migrations.RemoveField(
        #     model_name='intrabranchcollaborations',
        #     name='event_id',
        # ),
        # migrations.AlterField(
        #     model_name='event_logistic_items',
        #     name='event_id',
        #     field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='central_events.events'),
        # ),
        # migrations.AlterField(
        #     model_name='graphics_files',
        #     name='event_id',
        #     field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='central_events.events'),
        # ),
        # migrations.AlterField(
        #     model_name='graphics_links',
        #     name='event_id',
        #     field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='central_events.events'),
        # ),
        # migrations.AlterField(
        #     model_name='media_links',
        #     name='event_id',
        #     field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='central_events.events'),
        # ),
        # migrations.AlterField(
        #     model_name='media_selected_images',
        #     name='event_id',
        #     field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='central_events.events'),
        # ),
        # migrations.DeleteModel(
        #     name='Event_Permission',
        # ),
        # migrations.DeleteModel(
        #     name='Event_Proposal',
        # ),
        # migrations.DeleteModel(
        #     name='Event_Venue',
        # ),
        # migrations.DeleteModel(
        #     name='Events',
        # ),
        # migrations.DeleteModel(
        #     name='InterBranchCollaborations',
        # ),
        # migrations.DeleteModel(
        #     name='IntraBranchCollaborations',
        # ),
        # migrations.DeleteModel(
        #     name='SuperEvents',
        # ),
    ]
