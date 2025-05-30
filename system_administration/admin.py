from django.contrib import admin
from . models import adminUsers,MDT_Data_Access,Developer_criteria,Project_Developers,Project_leads,LAO_Data_Access,CWP_Data_Access,Promotions_Data_Access
from .models import WDT_Data_Access,Media_Data_Access,Graphics_Data_Access,Branch_Data_Access,FCT_Data_Access
from django.db import models
from django_json_widget.widgets import JSONEditorWidget
# Register your models here.

from . models import system
@admin.register(system)
class System(admin.ModelAdmin):
    list_display=['id','system_under_maintenance','main_website_under_maintenance','portal_under_maintenance','scheduling_under_maintenance','restrict_sc_ag_updates'
                 ,'count_down']

@admin.register(adminUsers)
class Admin(admin.ModelAdmin):
    list_display=['username','name','email']

@admin.register(MDT_Data_Access)
class Access_Criteria(admin.ModelAdmin):
    list_display=['ieee_id']

@admin.register(Developer_criteria)
class Developer_Criteria(admin.ModelAdmin):
    list_display=['id','developer_type']

@admin.register(Project_leads)
class Project_leads(admin.ModelAdmin):
    list_display=['name','developer_type']

@admin.register(Project_Developers)
class Project_Developer(admin.ModelAdmin):
    list_display=['name','developer_type']
@admin.register(LAO_Data_Access)
class LAO_Data_Access(admin.ModelAdmin):
    list_display=['ieee_id','manage_team_access']
@admin.register(CWP_Data_Access)
class CWP_Data_Access(admin.ModelAdmin):
    list_display=['ieee_id','manage_team_access']
@admin.register(Promotions_Data_Access)
class Prmotions_Data_Access(admin.ModelAdmin):
    list_display = ['ieee_id','manage_team_access']
@admin.register(WDT_Data_Access)
class WDT_Data_Access(admin.ModelAdmin):
    list_display = ['ieee_id','manage_team_access']
@admin.register(Media_Data_Access)
class Media_Data_Access(admin.ModelAdmin):
    list_display = ['ieee_id','manage_team_access']
@admin.register(Graphics_Data_Access)
class Graphics_Data_Access(admin.ModelAdmin):
    list_display = ['ieee_id','manage_team_access', 'event_access']
@admin.register(FCT_Data_Access)
class FCT_Data_Access(admin.ModelAdmin):
    list_display = ['ieee_id','manage_team_access']

@admin.register(Branch_Data_Access)
class Branch_Data_Access(admin.ModelAdmin):
    list_display=[
        'ieee_id','create_event_access','event_details_page_access','create_individual_task_access','create_team_task_access','create_panels_access',
        'panel_memeber_add_remove_access','team_details_page','manage_web_access','manage_custom_notification_access','manage_email_access'
    ]

from .models import SystemErrors
@admin.register(SystemErrors)
class SystemErrors(admin.ModelAdmin):
    list_display=[
        'pk','date_time','error_name','error_fix_status'
    ]

from .models import SC_AG_Data_Access
@admin.register(SC_AG_Data_Access)
class SC_AG_Data_Access(admin.ModelAdmin):
    list_display=['member','data_access_of']


# code for logging models in the admin interface.

from .models import General_Log
@admin.register(General_Log)
class General_LogAdmin(admin.ModelAdmin):
    list_display = ['id', 'content_type', 'object_id', 'update_number']
    list_filter = ['content_type']
    search_fields = ['object_id']

    formfield_overrides = {
        models.JSONField: {'widget': JSONEditorWidget(options={'mode': 'view'})},
    }
