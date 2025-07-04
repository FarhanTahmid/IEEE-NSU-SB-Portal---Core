from django.urls import path 
from . import views  

app_name = 'meeting_minutes'

##defining the urls to work with

urlpatterns = [

    # #team_meeting_minutes
    # path('',views.team_meeting_minutes, name='team_meeting_minutes'),
    # #branch_meeting_minutes
    # path('branch_meeting_minutes',views.branch_meeting_minutes, name='branch_meeting_minutes'),

    # #team_meeting_minutes_list
    # path('team_meeting_minutes_list',views.team_meeting_minutes_list,name='team_meeting_minutes_list'),
    # #branch_meeting_minutes_list
    # path('branch_meeting_minutes_list',views.branch_meeting_minutes_list,name='branch_meeting_minutes_list'),
    
    #meeting_minutes_homepage
    path('',views.meeting_minutes_homepage, name='meeting_minutes_homepage'),
    # Create a new meeting
    path('create/', views.meeting_minutes_create, name="meeting_minutes_create"),

    # Edit an existing meeting
    path('edit/<int:pk>/', views.meeting_minutes_edit, name="meeting_minutes_edit"), # needs pk
    path('meeting-minutes/<int:pk>/pdf/', views.download_meeting_pdf, name='download_meeting_pdf'),
]              
    
