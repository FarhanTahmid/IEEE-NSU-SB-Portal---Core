import json
from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
import requests
from content_writing_and_publications_team.forms import Content_Form
from content_writing_and_publications_team.renderData import ContentWritingTeam
from finance_and_corporate_team.manage_access import FCT_Render_Access
from finance_and_corporate_team.models import BudgetSheet
from finance_and_corporate_team.renderData import FinanceAndCorporateTeam
from graphics_team.models import Graphics_Banner_Image, Graphics_Link
from graphics_team.renderData import GraphicsTeam
from insb_port import settings
from main_website.renderData import HomepageItems
from media_team.models import Media_Images, Media_Link
from media_team.renderData import MediaTeam
from port.renderData import PortData
from public_relation_team.renderData import PRT_Data
from users import renderData
from users.renderData import Alumnis,PanelMembersData
from django.utils.datastructures import MultiValueDictKeyError
from django.http import HttpResponse
from .get_sc_ag_info import SC_AG_Info
from .renderData import Sc_Ag
from .manage_access import SC_Ag_Render_Access
from port.renderData import PortData
from system_administration.system_error_handling import ErrorHandling
from central_branch.renderData import Branch
from datetime import datetime
from django.http import Http404,HttpResponseBadRequest,JsonResponse
import logging
import traceback
from django.contrib.auth.decorators import login_required
from membership_development_team.models import Renewal_Sessions,Renewal_requests
from central_branch.view_access import Branch_View_Access
from django.contrib import messages
from central_events.models import Events, Google_Calendar_Attachments, InterBranchCollaborations, IntraBranchCollaborations, SuperEvents
from central_events.forms import EventForm, EventFormGC
from events_and_management_team.renderData import Events_And_Management_Team
from port.models import Chapters_Society_and_Affinity_Groups,Roles_and_Position
from users.models import Alumni_Members
from django.views.decorators.clickjacking import xframe_options_exempt
from content_writing_and_publications_team.models import Content_Team_Document, Content_Team_Documents_Link
from central_branch import views as cv
from users.renderData import LoggedinUser,member_login_permission
import xlwt
from system_administration.render_access import Access_Render
import re

# Create your views here.
logger=logging.getLogger(__name__)

@login_required
@member_login_permission
def sc_ag_homepage(request,primary):
    try:
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file

        
        # get the current panel of sc ag
        get_current_panel_of_sc_ag=SC_AG_Info.get_current_panel_of_sc_ag(request=request,sc_ag_primary=primary).first()
        sc_ag_eb_members=[]
        sc_ag_officers=[]
        sc_ag_volunteers=[]
        if(get_current_panel_of_sc_ag):
            sc_ag_eb_members=SC_AG_Info.get_sc_ag_executives_from_panels(request=request,panel_id=get_current_panel_of_sc_ag.pk)
            sc_ag_officers=SC_AG_Info.get_sc_ag_officers_from_panels(request=request,panel_id=get_current_panel_of_sc_ag.pk)
            sc_ag_volunteers=SC_AG_Info.get_sc_ag_volunteer_from_panels(request=request,panel_id=get_current_panel_of_sc_ag.pk)
        
        context={
            'user_data':user_data,
            'all_sc_ag':sc_ag,
            'sc_ag_info':get_sc_ag_info,
            'sc_ag_ebs':sc_ag_eb_members,
            'sc_ag_officers':sc_ag_officers,
            'sc_ag_volunteers':sc_ag_volunteers,
        }
        return render(request,'Homepage/sc_ag_homepage.html',context)
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def sc_ag_members(request,primary):
    
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        # get all insb members
        all_insb_members=renderData.get_all_registered_members(request=request)
        # get sc_ag_positions
        sc_ag_positions=PortData.get_positions_with_sc_ag_id(request,sc_ag_primary=primary)
        # get sc_ag teams
        sc_ag_teams=PortData.get_teams_of_sc_ag_with_id(request,primary)
        # get sc_ag members
        sc_ag_members=SC_AG_Info.get_sc_ag_members(request,primary)
        
        has_access_to_view_member_details=SC_Ag_Render_Access.access_for_member_details(request=request,sc_ag_primary=primary)

        if request.method=="POST":
            if request.POST.get('add_sc_ag_member'):
                position = request.POST['position']
                if position=='0':
                    position=None
                team=request.POST['team']
                if team=='0':
                    team=None
                member_ieee_id_list=request.POST.getlist('member_select')
                
                # Create Member for SC AG
                Sc_Ag.add_insb_members_to_sc_ag(ieee_id_list=member_ieee_id_list,
                                                position_id=position,
                                                sc_ag_primary=primary,
                                                team_pk=team,
                                                request=request)
                return redirect('chapters_and_affinity_group:sc_ag_members',primary)
            elif request.POST.get('remove_member'):
                member = request.POST['remove_sc_ag_member']
                Sc_Ag.remove_insb_member_from_sc_ag(request,sc_ag_primary=primary, ieee_id=member)
                return redirect('chapters_and_affinity_group:sc_ag_members',primary)
                    
        context={
            'user_data':user_data,
            'all_sc_ag':sc_ag,
            'sc_ag_info':get_sc_ag_info,
            'insb_members':all_insb_members,
            'positions':sc_ag_positions,
            'teams':sc_ag_teams,
            'sc_ag_members':sc_ag_members,
            'member_count':len(sc_ag_members),
            'has_access_to_view_member_details':has_access_to_view_member_details,            
        }
        return render(request,'Members/sc_ag_members.html',context=context)
    
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def sc_ag_panels(request,primary):

    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        
        # get panels of SC-AG
        all_panels=SC_AG_Info.get_panels_of_sc_ag(request=request,sc_ag_primary=primary)

        has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
        panel_edit_access=SC_Ag_Render_Access.access_for_panel_edit_access(request=request,sc_ag_primary=primary)
        
        show_restriction_banner = False
        #If there is edit access while update access is restricted from admin then show banner and override the edit access
        if not has_access_for_sc_ag_updates and panel_edit_access:
            show_restriction_banner = True
            panel_edit_access = False
        
        if request.method=="POST":
            if request.POST.get('create_panel'):
                tenure_year=request.POST['tenure_year']
                panel_start_date=request.POST['panel_start_date']
                panel_end_date=request.POST['panel_end_date']
                current_check=request.POST.get('current_check')
                if current_check is None:
                    current_check=False
                else:
                    current_check=True
                
                if(Sc_Ag.create_new_panel_of_sc_ag(request=request,
                                                current_check=current_check,
                                                panel_end_time=panel_end_date,
                                                panel_start_time=panel_start_date,
                                                sc_ag_primary=primary,tenure_year=tenure_year)
                ):
                    return redirect('chapters_and_affinity_group:sc_ag_panels',primary)  

        context={
            'user_data':user_data,
            'all_sc_ag':sc_ag,
            'sc_ag_info':get_sc_ag_info,
            'panels':all_panels,
            'panel_edit_access':panel_edit_access,
            'show_restriction_banner':show_restriction_banner
        }
        return render(request,'Panels/panel_homepage.html',context=context)
    
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def sc_ag_panel_details(request,primary,panel_pk):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        
        # get sc_ag members
        sc_ag_members=SC_AG_Info.get_sc_ag_members(request,primary)
        
        # get panel information
        panel_info=Branch.load_panel_by_id(panel_pk)
        # getting tenure time
        if(panel_info.panel_end_time is None):
            present_date=datetime.now()
            tenure_time=present_date.date()-panel_info.creation_time.date()
        else:
            tenure_time=panel_info.panel_end_time.date()-panel_info.creation_time.date()

        # get sc_ag_executives
        sc_ag_eb_members=SC_AG_Info.get_sc_ag_executives_from_panels(request=request,panel_id=panel_pk)

        has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
        panel_edit_access = SC_Ag_Render_Access.access_for_panel_edit_access(request=request,sc_ag_primary=primary)
        
        show_restriction_banner = False
        #If there is edit access while update access is restricted from admin then show banner and override the edit access
        if not has_access_for_sc_ag_updates and panel_edit_access:
            show_restriction_banner = True
            panel_edit_access = False

        if request.method=="POST":
            # adding member to panel
            if request.POST.get('add_executive_to_sc_ag_panel'):
                member_select_list=request.POST.getlist('member_select')
                position=request.POST.get('sc_ag_eb_position')
                # Add Executive members to panel, keeping team=None
                if(Sc_Ag.add_sc_ag_members_to_panel(memberList=member_select_list,panel_id=panel_pk,position_id=position,request=request,team=None,sc_ag_primary=primary)):
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details',primary,panel_pk)
            # removing member from panel
            if request.POST.get('remove_member'):
                member_to_remove=request.POST['remove_panel_member']
                if(Sc_Ag.remove_sc_ag_member_from_panel(request=request,member_ieee_id=member_to_remove,panel_id=panel_pk,sc_ag_primary=primary)):
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details',primary,panel_pk)
                else:
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details',primary,panel_pk)

            
            # Delete panel
            if(request.POST.get('delete_panel')):
                if(Sc_Ag.delete_sc_ag_panel(request=request,panel_pk=panel_pk,sc_ag_primary=primary)):
                    return redirect('chapters_and_affinity_group:sc_ag_panels',primary)
            
            # update panel settings
            if(request.POST.get('save_changes')):
                panel_tenure=request.POST['panel_tenure']
                current_panel_check=request.POST.get('current_panel_check')
                if current_panel_check is None:
                    current_panel_check=False
                else:
                    current_panel_check=True
                panel_start_date=request.POST['panel_start_date']
                panel_end_date=request.POST['panel_end_date']
                if(Sc_Ag.update_sc_ag_panel(is_current_check=current_panel_check,panel_end_date=panel_end_date,panel_pk=panel_pk,panel_start_date=panel_start_date,panel_tenure=panel_tenure,request=request,sc_ag_primary=primary)):
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details',primary,panel_pk)
            
            #Create Positions
            if(request.POST.get('create_position')):
                mentor_position_check=request.POST.get('mentor_position_check')
                if mentor_position_check is None:
                    mentor_position_check=False
                else:
                    mentor_position_check=True
                    
                officer_position_check=request.POST.get('officer_position_check')
                if officer_position_check is None:
                    officer_position_check=False
                else:
                    officer_position_check=True
                    
                coordinator_position_check=request.POST.get('coordinator_position_check')
                if coordinator_position_check is None:
                    coordinator_position_check=False
                else:
                    coordinator_position_check=True
                
                sc_ag_executive_position_check=request.POST.get('sc_ag_executive_position_check')
                if sc_ag_executive_position_check is None:
                    sc_ag_executive_position_check=False
                else:
                    sc_ag_executive_position_check=True
             
                faculty_position_check=request.POST.get('faculty_position_check')
                if faculty_position_check is None:
                    faculty_position_check=False
                else:
                    faculty_position_check=True

                core_volunteer_position_check = request.POST.get('core_volunteer_position_check')
                if core_volunteer_position_check is None:
                    core_volunteer_position_check = False
                else:
                    core_volunteer_position_check = True

                volunteer_position_check = request.POST.get('volunteer_position_check')
                if volunteer_position_check is None:
                    volunteer_position_check = False
                else:
                    volunteer_position_check = True
                    
                position_name=request.POST['position_name']
                # create new Position
                if(PortData.create_positions(request=request,sc_ag_primary=primary,
                                          is_eb_member=False,
                                          is_officer=officer_position_check,
                                          is_sc_ag_eb_member=sc_ag_executive_position_check,is_mentor=mentor_position_check,
                                          is_faculty=faculty_position_check,is_co_ordinator=coordinator_position_check,role=position_name,
                                          is_core_volunteer=core_volunteer_position_check,is_volunteer=volunteer_position_check)):
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details',primary,panel_pk)
            
            # update existing positions
            if(request.POST.get('update_position')):
                mentor_position_check=request.POST.get('mentor_position_check')
                if mentor_position_check is None:
                    mentor_position_check=False
                else:
                    mentor_position_check=True
                    
                officer_position_check=request.POST.get('officer_position_check')
                if officer_position_check is None:
                    officer_position_check=False
                else:
                    officer_position_check=True
                    
                coordinator_position_check=request.POST.get('coordinator_position_check')
                if coordinator_position_check is None:
                    coordinator_position_check=False
                else:
                    coordinator_position_check=True
                
                executive_position_check=request.POST.get('executive_position_check')
                if executive_position_check is None:
                    executive_position_check=False
                else:
                    executive_position_check=True
                
                faculty_position_check=request.POST.get('faculty_position_check')
                if faculty_position_check is None:
                    faculty_position_check=False
                else:
                    faculty_position_check=True

                core_volunteer_position_check = request.POST.get('core_volunteer_position_check')
                if core_volunteer_position_check is None:
                    core_volunteer_position_check = False
                else:
                    core_volunteer_position_check = True

                volunteer_position_check = request.POST.get('volunteer_position_check')
                if volunteer_position_check is None:
                    volunteer_position_check = False
                else:
                    volunteer_position_check = True
                    
                position_name=request.POST['position_name']
                position_rank=request.POST['position_rank']
                position_id=request.POST.get('position_to_edit')
                
                # update Position
                try:    
                    if(Roles_and_Position.objects.filter(id=int(position_id)).update(
                        role=position_name,rank=position_rank,
                        is_eb_member=False,is_sc_ag_eb_member=executive_position_check,is_officer=officer_position_check,is_co_ordinator=coordinator_position_check,
                        is_faculty=faculty_position_check,is_mentor=mentor_position_check,is_core_volunteer=core_volunteer_position_check,is_volunteer=volunteer_position_check
                    )):
                        messages.success(request,f"Position {position_name} was updated!")
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details',primary,panel_pk)
                except Exception as e:
                    logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
                    ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
                    messages.warning(request,"Something went wrong! Please Try again!")
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details',primary,panel_pk)
            # delete positions
            if(request.POST.get('delete_position')):
                position_name=request.POST['position_name']
                position_id=request.POST.get('position_to_edit')
                try:
                    if(Roles_and_Position.objects.filter(id=int(position_id)).delete()):
                        messages.warning(request,f'The position {position_name} has been deleted.')
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details',primary,panel_pk)
                except Exception as e:
                    logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
                    ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
                    messages.warning(request,"Something went wrong! Please Try again!")
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details',primary,panel_pk)
            
            #Create New TEam
            if(request.POST.get('create_team')):
                team_name=request.POST['team_name']
                if(PortData.create_team(
                    request=request,sc_ag_primary=primary,team_name=team_name
                )):
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details',primary,panel_pk)

 
        context={
            'user_data':user_data,
            'all_sc_ag':sc_ag,
            'sc_ag_info':get_sc_ag_info,
            'panel_info':panel_info,
            'tenure_time':tenure_time,
            'sc_ag_members':sc_ag_members,
            'sc_ag_eb_members':sc_ag_eb_members,
            'sc_ag_eb_positions':SC_AG_Info.get_sc_ag_executive_positions(request=request,sc_ag_primary=primary),
            'panel_edit_access':panel_edit_access,
            'show_restriction_banner':show_restriction_banner,
            'member_details_access':SC_Ag_Render_Access.access_for_member_details(request=request,sc_ag_primary=primary),
            'all_positions':PortData.get_all_positions_of_everyone(request=request,sc_ag_primary=primary)
        }
        return render(request,'Panels/sc_ag_executive_members_tab.html',context=context)
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request) 
       

@login_required  
@member_login_permission             
def sc_ag_panel_details_officers_tab(request,primary,panel_pk):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)

        # get panel information
        panel_info=Branch.load_panel_by_id(panel_pk)
        # getting tenure time
        if(panel_info.panel_end_time is None):
            present_date=datetime.now()
            tenure_time=present_date.date()-panel_info.creation_time.date()
        else:
            tenure_time=panel_info.panel_end_time.date()-panel_info.creation_time.date()

        # get sc_ag_officer members
        sc_ag_officer_members_in_panel=SC_AG_Info.get_sc_ag_officers_from_panels(panel_id=panel_pk,request=request)
        # get sc_ag members
        sc_ag_members=SC_AG_Info.get_sc_ag_members(request,primary)

        has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
        panel_edit_access = SC_Ag_Render_Access.access_for_panel_edit_access(request=request,sc_ag_primary=primary)
        
        show_restriction_banner = False
        #If there is edit access while update access is restricted from admin then show banner and override the edit access
        if not has_access_for_sc_ag_updates and panel_edit_access:
            show_restriction_banner = True
            panel_edit_access = False
        
        if(request.method=="POST"):
            # Add Member to officer panel
            if(request.POST.get('add_officer_to_sc_ag_panel')):
                member_select_list=request.POST.getlist('member_select')
                position=request.POST.get('sc_ag_officer_position')
                team=request.POST.get('sc_ag_team')
                if(Sc_Ag.add_sc_ag_members_to_panel(memberList=member_select_list,panel_id=panel_pk,position_id=position,team=team,sc_ag_primary=primary,request=request)):
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details_officers', primary,panel_pk)
            
            # Remove Member from Panel
            if request.POST.get('remove_member_officer'):
                member_to_remove=request.POST['remove_officer_member']
                if(Sc_Ag.remove_sc_ag_member_from_panel(request=request,member_ieee_id=member_to_remove,panel_id=panel_pk,sc_ag_primary=primary)):
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details_officers',primary,panel_pk)
            
            
        context={
            'user_data':user_data,
            'all_sc_ag':sc_ag,
            'sc_ag_info':get_sc_ag_info,
            'panel_info':panel_info,
            'tenure_time':tenure_time,
            'sc_ag_members':sc_ag_members,
            'sc_ag_officer_member':sc_ag_officer_members_in_panel,
            'sc_ag_officer_positions':SC_AG_Info.get_sc_ag_officer_positions(request=request,sc_ag_primary=primary),
            'sc_ag_teams':SC_AG_Info.get_teams_of_sc_ag(request=request,sc_ag_primary=primary),
            'member_details_access':SC_Ag_Render_Access.access_for_member_details(request=request,sc_ag_primary=primary),
            'panel_edit_access':panel_edit_access,
            'show_restriction_banner':show_restriction_banner,

        }
        return render(request,'Panels/sc_ag_officer_members_tab.html',context=context)
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
        
        
@login_required   
@member_login_permission 
def sc_ag_panel_details_volunteers_tab(request,primary,panel_pk):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)

        # get panel information
        panel_info=Branch.load_panel_by_id(panel_pk)
        # getting tenure time
        if(panel_info.panel_end_time is None):
            present_date=datetime.now()
            tenure_time=present_date.date()-panel_info.creation_time.date()
        else:
            tenure_time=panel_info.panel_end_time.date()-panel_info.creation_time.date()

        # get sc_ag members
        sc_ag_members=SC_AG_Info.get_sc_ag_members(request,primary)
        # get sc ag volunteer positions
        sc_ag_volunteer_positions=PortData.get_all_volunteer_position_with_sc_ag_id(request=request,sc_ag_primary=primary)
        
        # get_sc_ag_officer members from panels
        sc_ag_volunteer_members_in_panel=SC_AG_Info.get_sc_ag_volunteer_from_panels(request=request,panel_id=panel_pk)
        
        has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
        panel_edit_access = SC_Ag_Render_Access.access_for_panel_edit_access(request=request,sc_ag_primary=primary)
        
        show_restriction_banner = False
        #If there is edit access while update access is restricted from admin then show banner and override the edit access
        if not has_access_for_sc_ag_updates and panel_edit_access:
            show_restriction_banner = True
            panel_edit_access = False

        if(request.method=="POST"):
            # Add Member to officer panel
            if(request.POST.get('add_volunteer_to_sc_ag_panel')):
                member_select_list=request.POST.getlist('member_select')
                position=request.POST.get('sc_ag_volunteer_position')
                team=request.POST.get('sc_ag_team')
                if(Sc_Ag.add_sc_ag_members_to_panel(memberList=member_select_list,panel_id=panel_pk,position_id=position,team=team,sc_ag_primary=primary,request=request)):
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details_volunteers', primary,panel_pk)
            
            # Remove Member from Panel
            if request.POST.get('remove_member_volunteer'):
                member_to_remove=request.POST['remove_volunteer_member']
                if(Sc_Ag.remove_sc_ag_member_from_panel(request=request,member_ieee_id=member_to_remove,panel_id=panel_pk,sc_ag_primary=primary)):
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details_volunteers', primary,panel_pk)

        
        
        
        context={           
            'user_data':user_data,
            'all_sc_ag':sc_ag,
            'sc_ag_info':get_sc_ag_info,
            'panel_info':panel_info,
            'tenure_time':tenure_time,
            'sc_ag_members':sc_ag_members,
            'sc_ag_volunteer_positions':sc_ag_volunteer_positions,
            'sc_ag_teams':SC_AG_Info.get_teams_of_sc_ag(request=request,sc_ag_primary=primary),
            'sc_ag_volunteer_members':sc_ag_volunteer_members_in_panel,
            'member_details_access':SC_Ag_Render_Access.access_for_member_details(request=request,sc_ag_primary=primary),
            'panel_edit_access':panel_edit_access,
            'show_restriction_banner':show_restriction_banner

        }
        return render(request,'Panels/sc_ag_volunteer_members_tab.html',context=context)
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def sc_ag_panel_details_alumni_members_tab(request,primary,panel_pk):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)

        # get panel information
        panel_info=Branch.load_panel_by_id(panel_pk)
        # getting tenure time
        if(panel_info.panel_end_time is None):
            present_date=datetime.now()
            tenure_time=present_date.date()-panel_info.creation_time.date()
        else:
            tenure_time=panel_info.panel_end_time.date()-panel_info.creation_time.date()

        has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
        panel_edit_access = SC_Ag_Render_Access.access_for_panel_edit_access(request=request,sc_ag_primary=primary)
        
        show_restriction_banner = False
        #If there is edit access while update access is restricted from admin then show banner and override the edit access
        if not has_access_for_sc_ag_updates and panel_edit_access:
            show_restriction_banner = True
            panel_edit_access = False

        # get all alumni members registered in database of IEEE NSU SB
        alumni_members=Alumni_Members.objects.all().order_by('pk')
        
        if(request.POST.get('create_new_alumni')):
            try:
                alumni_name=request.POST['alumni_name']
                alumni_email=request.POST['alumni_email']
                alumni_contact_no=request.POST['alumni_contact_no']
                alumni_facebook_link=request.POST['alumni_facebook_link']
                alumni_linkedin_link=request.POST['alumni_linkedin_link']
                alumni_picture=request.FILES.get('alumni_picture')

            except MultiValueDictKeyError:
                messages.error(request,"Image can not be uploaded!")
            finally:
                # create alumni
                if(Alumnis.create_alumni_members(
                    request=request,contact_no=alumni_contact_no,
                    email=alumni_email,
                    facebook_link=alumni_facebook_link,
                    linkedin_link=alumni_linkedin_link,
                    name=alumni_name,
                    picture=alumni_picture)):
                    return redirect('chapters_and_affinity_group:sc_ag_panel_details_alumni',primary,panel_pk)
                else:
                    messages.warning(request,'Failed to Add new alumni!')
        if(request.POST.get('add_alumni_to_panel')):
            alumni_to_add=request.POST.getlist('alumni_select')
            position=request.POST['alumni_position']
            for i in alumni_to_add:            
                if(PanelMembersData.add_alumns_to_branch_panel(request=request,alumni_id=i,panel_id=panel_pk,position=position)):
                    pass
        if(request.POST.get('remove_member_alumni')):
            alumni_to_remove=request.POST['remove_alumni_member']
            if(PanelMembersData.remove_alumns_from_branch_panel(request=request,member_to_remove=alumni_to_remove,panel_id=panel_pk)):
                pass        
        
        context={
            'user_data':user_data,
            'all_sc_ag':sc_ag,
            'sc_ag_info':get_sc_ag_info,
            'panel_info':panel_info,
            'tenure_time':tenure_time,
            'positions':SC_AG_Info.get_sc_ag_executive_positions(request=request,sc_ag_primary=primary),
            'alumni_members':alumni_members,
            'alumni_members_in_panel':PanelMembersData.get_alumni_members_from_panel(panel=panel_pk,request=request),
            'panel_edit_access':panel_edit_access,
            'show_restriction_banner':show_restriction_banner
        }
        return render(request,'Panels/sc_ag_alumni_members_tab.html',context=context)
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
@login_required
@member_login_permission
def sc_ag_membership_renewal_sessions(request,primary):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        has_access = SC_Ag_Render_Access.access_for_membership_renewal_access(request=request,sc_ag_primary=primary)
        if has_access:
            #Load all sessions at first from Central Branch
            sessions=Renewal_Sessions.objects.order_by('-id')
            
            context={
                'user_data':user_data,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'sessions':sessions,
                'is_branch':False,            
            }
            return render(request,"Renewal/renewal_homepage.html",context=context)
        else:
            return render(request,"access_denied.html", { 'all_sc_ag':sc_ag })
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def sc_ag_renewal_session_details(request,primary,renewal_session):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        if(SC_Ag_Render_Access.access_for_membership_renewal_access(request=request,sc_ag_primary=primary)):
            
            get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
            # get the session
            renewal_session=Renewal_Sessions.objects.get(pk=renewal_session)
            
            if(int(primary)==2):
                get_renewal_requests=Renewal_requests.objects.filter(session_id=renewal_session,pes_renewal_check=True).values('id','name','email_associated','email_ieee','contact_no','ieee_id','renewal_status').order_by('id')
            elif(int(primary)==3):
                get_renewal_requests=Renewal_requests.objects.filter(session_id=renewal_session,ras_renewal_check=True).values('id','name','email_associated','email_ieee','contact_no','ieee_id','renewal_status').order_by('id')
            elif(int(primary)==4):
                get_renewal_requests=Renewal_requests.objects.filter(session_id=renewal_session,ias_renewal_check=True).values('id','name','email_associated','email_ieee','contact_no','ieee_id','renewal_status').order_by('id')
            elif(int(primary)==5):
                get_renewal_requests=Renewal_requests.objects.filter(session_id=renewal_session,wie_renewal_check=True).values('id','name','email_associated','email_ieee','contact_no','ieee_id','renewal_status').order_by('id')

            context={
                'user_data':user_data,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'is_branch':False,
                'session_id':renewal_session.pk,
                'session_info':renewal_session,
                'requests':get_renewal_requests,
            }
            return render(request,"Renewal/SC-AG Renewals/sc_ag_renewal_details.html",context=context)
        else:
            return render(request,"access_denied.html", { 'all_sc_ag':sc_ag })

    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def get_sc_ag_renewal_stats(request):
    
    if request.method=="GET":
        # get the renewal session id from the URL
        seek_value=request.GET.get('seek_value')
        # splitting the seek value by '-' to get sc_ag_primary and renewal session id.
        seek_value=seek_value.split('-')
        # get the sc_ag_primary and renewal session id
        sc_ag_primary=seek_value[0]
        renewal_session_id=seek_value[1]
        
        try:
            # get the sc_ag_info of total renewal for the session
            if(int(sc_ag_primary)==2):
                renewal_count=Renewal_requests.objects.filter(session_id=renewal_session_id,pes_renewal_check=True,renewal_status=True).count()
                renewal_left=Renewal_requests.objects.filter(session_id=renewal_session_id,pes_renewal_check=True,renewal_status=False).count()
            if(int(sc_ag_primary)==3):
                renewal_count=Renewal_requests.objects.filter(session_id=renewal_session_id,ras_renewal_check=True,renewal_status=True).count()
                renewal_left=Renewal_requests.objects.filter(session_id=renewal_session_id,ras_renewal_check=True,renewal_status=False).count()
            if(int(sc_ag_primary)==4):
                renewal_count=Renewal_requests.objects.filter(session_id=renewal_session_id,ias_renewal_check=True,renewal_status=True).count()
                renewal_left=Renewal_requests.objects.filter(session_id=renewal_session_id,ias_renewal_check=True,renewal_status=False).count()
            if(int(sc_ag_primary)==5):
                renewal_count=Renewal_requests.objects.filter(session_id=renewal_session_id,wie_renewal_check=True,renewal_status=True).count()
                renewal_left=Renewal_requests.objects.filter(session_id=renewal_session_id,wie_renewal_check=True,renewal_status=False).count()

            
            context={
                    "labels":["Complete Renewals","Incomplete Renewals"],
                    "values":[renewal_count,renewal_left]
                    }
            return JsonResponse(context)
        except Exception as e:
            logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            return cv.custom_500(request)
        
@login_required
@member_login_permission
def sc_ag_manage_access(request,primary):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        if(SC_Ag_Render_Access.access_for_manage_access(request=request,sc_ag_primary=primary)):
            # get sc ag info
            get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
            
            # get SC AG members
            get_sc_ag_members=SC_AG_Info.get_sc_ag_members(request=request,sc_ag_primary=primary)
            # get data access Members
            get_data_access_members=Sc_Ag.get_data_access_members(request=request,sc_ag_primary=primary)
            
            if(request.method=="POST"):
                # Adding member to data access Table
                if(request.POST.get('add_data_access_member')):
                    member_select_list=request.POST.getlist('member_select')
                    if(Sc_Ag.add_sc_ag_member_to_data_access(request=request,member_list=member_select_list,sc_ag_primary=primary)):
                        return redirect('chapters_and_affinity_group:sc_ag_manage_access',primary)
                # Updating view access for data access member
                if(request.POST.get('access_update')):
                    member=request.POST['access_ieee_id']
                    
                    # data access values
                    member_details_access=False
                    create_event_access=False
                    event_details_edit_access=False
                    panel_edit_access=False
                    membership_renewal_access=False
                    manage_web_access=False
                    manage_access=False
                    
                    # get values from template and change according to it
                    if(request.POST.get('member_details_access') is not None):
                        member_details_access=True
                    if(request.POST.get('create_event_access') is not None):
                        create_event_access=True
                    if(request.POST.get('event_details_edit_access') is not None):
                        event_details_edit_access=True
                    if(request.POST.get('panel_edit_access') is not None):
                        panel_edit_access=True
                    if(request.POST.get('membership_renewal_access') is not None):
                        membership_renewal_access=True
                    if(request.POST.get('manage_web_access') is not None):
                        manage_web_access=True
                    if(request.POST.get('manage_access') is not None):
                        manage_access=True
                    
                    # sending values to functions as kwargs. To further addition to Data access just pass the attribute of model=attribute value(e.g:member_details_access=member_details_access(True/False)) to the function
                    if(Sc_Ag.update_sc_ag_member_access(request=request,member=member,sc_ag_primary=primary,
                                                        member_details_access=member_details_access,
                                                        create_event_access=create_event_access,
                                                        event_details_edit_access=event_details_edit_access,
                                                        panel_edit_access=panel_edit_access,
                                                        membership_renewal_access=membership_renewal_access,
                                                        manage_web_access=manage_web_access,
                                                        manage_access=manage_access)):
                        return redirect('chapters_and_affinity_group:sc_ag_manage_access',primary)
                    else:
                        return redirect('chapters_and_affinity_group:sc_ag_manage_access',primary)

                # remove member from data access
                if(request.POST.get('remove_from_data_access')):
                    member_to_remove=request.POST['access_ieee_id']
                    
                    if(Sc_Ag.remove_member_from_data_access(request=request,member=member_to_remove,sc_ag_primary=primary)):
                        return redirect('chapters_and_affinity_group:sc_ag_manage_access',primary)
                    else:
                        return redirect('chapters_and_affinity_group:sc_ag_manage_access',primary)          
            context={
                'user_data':user_data,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'sc_ag_members':get_sc_ag_members,
                'data_access_members':get_data_access_members,
            }
            return render(request,'Manage Access/sc_ag_manage_access.html',context=context)       
        else:
            return render(request,'access_denied.html', { 'all_sc_ag':sc_ag })
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
def sc_ag_renewal_excel_sheet(request,primary,renewal_session):
    try:
        has_access = SC_Ag_Render_Access.access_for_membership_renewal_access(request=request,sc_ag_primary=primary)
        if has_access:
            response=Sc_Ag.generate_renewal_excel_sheet(request=request,renewal_session_id=renewal_session,sc_ag_primary=primary)
            if(not response):
                return redirect('chapters_and_affinity_group:sc_ag_membership_renewal_details',primary,renewal_session)
            else:
                return response
        else:
            return render(request,'access_denied.html')
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
        
@login_required
@member_login_permission
def event_control_homepage(request,primary):

    '''This is the event control homepage view function for rest of the groups, except 1'''

    try:
        sc_ag=PortData.get_all_sc_ag(request=request)
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        is_branch= False

        has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
        has_access_to_create_event=SC_Ag_Render_Access.access_for_create_event(request=request,sc_ag_primary=primary)
        
        show_restriction_banner = False
        #If there is create access while update access is restricted from admin then show banner and override the create access
        if not has_access_for_sc_ag_updates and has_access_to_create_event:
            show_restriction_banner = True
            has_access_to_create_event = False
        
        #loading all events for society affinity groups now
        events= Branch.load_all_inter_branch_collaborations_with_events(primary)
        all_event_years = Branch.get_event_years(primary)
        if request.method=="POST":
            if request.POST.get('add_event_type'):
                event_type = request.POST.get('event_type')
                created_event_type = Branch.add_event_type_for_group(event_type,primary)
                if created_event_type:
                    print("Event type did not exists, so new event was created")
                    messages.info(request,"New Event Type Added Successfully")
                else:
                    print("Event type already existed")
                    messages.info(request,"Event Type Already Exists")
                return redirect('chapters_and_affinity_group:event_control_homepage',primary)


        context={
            'user_data':user_data,
            'all_sc_ag':sc_ag,
            'sc_ag_info':get_sc_ag_info,
            'is_branch':is_branch,
            'has_access_to_create_event':has_access_to_create_event,
            'events':events,
            'all_event_years':all_event_years,
            # TODO:
            # if dont have event edit access, make people redirect to event in main web
            'has_access_to_edit_event':SC_Ag_Render_Access.access_for_event_details_edit(request=request,sc_ag_primary=primary),
            'common_access':SC_Ag_Render_Access.get_sc_ag_common_access(request,primary),
            'show_restriction_banner':show_restriction_banner
            
        }
        return render(request,"Events/event_homepage.html",context)
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
def mega_event_creation(request, primary):

    '''function for creating super event'''

    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file

        sc_ag=PortData.get_all_sc_ag(request=request)
        has_access = SC_Ag_Render_Access.access_for_create_event(request, primary)
        has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
        
        #If there is create access while update access is restricted from admin then override the create access
        if not has_access_for_sc_ag_updates and has_access:
            has_access = False

        if has_access:
            get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
            is_branch= False
            context={
                'user_data':user_data,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'is_branch':is_branch,
                'allowed_image_upload':1
            }

            if request.method == "POST":

                '''Checking to see if either of the submit or cancelled button has been clicked'''

                if (request.POST.get('Submit')):

                    '''Getting data from page and saving them in database'''

                    super_event_name = request.POST.get('super_event_name')
                    super_event_description = request.POST.get('super_event_description')
                    start_date = request.POST.get('probable_date')
                    end_date = request.POST.get('final_date')
                    banner_image = request.FILES.get('image')
                    if(Branch.register_mega_events(primary,super_event_name,super_event_description,start_date,end_date,banner_image)):
                        messages.info(request,"New Mega Event Added Successfully")
                    else:
                        messages.warning(request,"Something went wrong while creating the event")
                    return redirect('chapters_and_affinity_group:mega_events', primary)
                
            return render(request,"Events/Super Event/super_event_creation_form.html", context)
        else:
            return render(request, 'access_denied.html', { 'all_sc_ag':sc_ag, 'user_data':user_data })
        
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
def mega_events(request,primary):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file

        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
        has_access_to_create_event=SC_Ag_Render_Access.access_for_create_event(request=request,sc_ag_primary=primary)
        
        show_restriction_banner = False
        #If there is create access while update access is restricted from admin then show banner and override the create access
        if not has_access_for_sc_ag_updates and has_access_to_create_event:
            show_restriction_banner = True
            has_access_to_create_event = False

        mega_events = SuperEvents.objects.filter(mega_event_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=primary)).order_by('-pk')

        context = {
            'is_branch':False,
            'mega_events':mega_events,
            'user_data':user_data,
            'all_sc_ag':sc_ag,
            'sc_ag_info':get_sc_ag_info,
            'has_access_to_create_event':has_access_to_create_event,
            'show_restriction_banner':show_restriction_banner
        }

        return render(request,"Events/Super Event/super_event_table.html",context)
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
def mega_event_edit(request,primary,mega_event_id):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file

        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)

        has_access = SC_Ag_Render_Access.access_for_event_details_edit(request,primary)
        if has_access:
            has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
            show_restriction_banner = False
            if not has_access_for_sc_ag_updates:
                show_restriction_banner = True

            mega_event = Branch.get_mega_event(mega_event_id,primary)

            if request.method == 'POST':
                if request.POST.get('Submit'):
                    super_event_name = request.POST.get('super_event_name')
                    super_event_description = request.POST.get('super_event_description')
                    start_date = request.POST.get('probable_date')
                    end_date = request.POST.get('final_date')
                    publish_mega_event = request.POST.get('publish_event')
                    banner_image = request.FILES.get('image')

                    if(Branch.update_mega_event(mega_event_id,super_event_name,super_event_description,start_date,end_date,publish_mega_event,banner_image)):
                        messages.success(request,'Event details updated successfully')
                    else:
                        messages.warning(request,'Something went wrong while updating the event details')

                    return redirect('chapters_and_affinity_group:mega_event_edit',primary, mega_event_id)
                elif request.POST.get('delete_image'):
                    if(Branch.delete_mega_event_banner(mega_event_id)):
                        messages.success(request,'Banner Image removed successfully')
                    else:
                        messages.warning(request,'Something went wrong while deleting the image')
                    return redirect('chapters_and_affinity_group:mega_event_edit',primary, mega_event_id)
                elif request.POST.get('delete_event'):
                    if(Branch.delete_mega_event(mega_event_id)):
                        messages.info(request,'Mega event deleted successfully')
                    else:
                        messages.warning(request,'Something went wrong while deleting the event')
                    return redirect('chapters_and_affinity_group:mega_events',primary)

            if mega_event.banner_image:
                image_number = 1
            else:
                image_number = 0

            context = {
                'primary':primary,
                'is_branch':False,
                'mega_event':mega_event,
                'user_data':user_data,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'allowed_image_upload':1-image_number,
                'show_restriction_banner':show_restriction_banner,
                'has_access_for_sc_ag_updates':has_access_for_sc_ag_updates
            }

            return render(request,"Events/Super Event/super_event_edit_form.html",context)
        else:
            return redirect('main_website:mega_event_description_page',mega_event_id)
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
def mega_event_add_event(request,primary,mega_event_id):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)

        has_access = SC_Ag_Render_Access.access_for_event_details_edit(request,primary)
        if has_access:
            has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
            show_restriction_banner = False
            if not has_access_for_sc_ag_updates:
                show_restriction_banner = True

            mega_event = Branch.get_mega_event(mega_event_id,primary)
            all_insb_events_with_interbranch_collaborations = Branch.load_all_inter_branch_collaborations_with_events(primary)
            filtered_events_with_collaborations = Branch.events_not_registered_to_mega_events(all_insb_events_with_interbranch_collaborations)
            events_of_mega_Event = Branch.get_events_of_mega_event(mega_event)

            if request.method == "POST":

                if request.POST.get('add_event_to_mega_event'):

                    event_list = request.POST.getlist('selected_events')
                    if Branch.add_events_to_mega_event(event_list,mega_event):
                        messages.success(request,f"Events Added Successfully to {mega_event.super_event_name}")
                    else:
                        messages.error(request,"Error occured!")

                    return redirect("chapters_and_affinity_group:mega_event_add_event",primary,mega_event_id)
                
                if request.POST.get('remove'):

                    event_id = request.POST.get('remove_event')
                    if Branch.delete_event_from_mega_event(event_id):
                        messages.success(request,f"Event deleted Successfully from {mega_event.super_event_name}")
                    else:
                        messages.error(request,"Error occured!")

                    return redirect("chapters_and_affinity_group:mega_event_add_event",primary,mega_event_id)

            context = {
                'primary':primary,
                'is_branch':False,
                'user_data':user_data,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'mega_event':mega_event,
                'events':filtered_events_with_collaborations,
                'events_of_mega_event':events_of_mega_Event,
                'show_restriction_banner':show_restriction_banner,
                'has_access_for_sc_ag_updates':has_access_for_sc_ag_updates
            }

            return render(request,"Events/Super Event/super_event_add_event_form_tab.html",context)
        else:
            return render(request,'access_denied.html', {'user_data':user_data, 'all_sc_ag':sc_ag})
    
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def event_creation_form_page(request,primary):
    #######load data to show in the form boxes#########
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        has_access = SC_Ag_Render_Access.access_for_create_event(request, primary)
        has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
        
        #If there is create access while update access is restricted from admin then override the create access
        if not has_access_for_sc_ag_updates and has_access:
            has_access = False

        if has_access:
            get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
            is_branch=False
            form = EventForm()
            sc_ag=PortData.get_all_sc_ag(request=request)
            #loading super/mother event at first and event categories for Group 1 only (IEEE NSU Student Branch)
            super_events=Branch.load_all_mother_events()
            event_types=Branch.load_all_event_type_for_groups(primary)
            context={
                'user_data':user_data,
                'super_events':super_events,
                'event_types':event_types,
                'all_sc_ag':sc_ag,
                'form':form,
                'is_branch':is_branch,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
            }
            '''function for creating event'''

            if(request.method=="POST"):

                ''' Checking to see if the next button is clicked '''

                if(request.POST.get('next')):


                    '''Getting data from page and calling the register_event_page1 function to save the event page 1 to database'''

                    super_event_id=request.POST.get('super_event')
                    event_name=request.POST['event_name']
                    event_description=request.POST['event_description']
                    event_type_list = request.POST.getlist('event_type')
                    event_start_date=request.POST['start_date_time']
                    event_end_date=request.POST['end_date_time']
                
                    #It will return True if register event page 1 is success
                    get_event=Branch.register_event_page1(
                        super_event_id=super_event_id,
                        event_name=event_name,
                        event_type_list=event_type_list,
                        event_description=event_description,
                        event_start_date=event_start_date,
                        event_end_date=event_end_date,
                        event_organiser=Chapters_Society_and_Affinity_Groups.objects.get(primary=primary).primary
                    )
                    
                    if(get_event)==False:
                        messages.info(request,"Database Error Occured! Please try again later.")
                    else:
                        #if the method returns true, it will redirect to the new page
                        return redirect('chapters_and_affinity_group:event_creation_form2',primary,get_event)
                elif(request.POST.get('add_event_type')):
                    ''' Adding a new event type '''
                    event_type = request.POST.get('event_type')
                    created_event_type = Branch.add_event_type_for_group(event_type,primary)
                    if created_event_type:
                        print("Event type did not exists, so new event was created")
                        messages.success(request,"New Event Type Added Successfully")
                    else:
                        print("Event type already existed")
                        messages.info(request,"Event Type Already Exists")
                    return redirect('chapters_and_affinity_group:event_creation_form1', primary)

            return render(request,'Events/event_creation_form.html',context)
        else:
            return render(request,'access_denied.html', {'user_data':user_data, 'all_sc_ag':sc_ag})
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def event_creation_form_page2(request,primary,event_id):
    #loading all inter branch collaboration Options

    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        print(request.META.get("HTTP_REFERER"))
        sc_ag=PortData.get_all_sc_ag(request=request)
        has_access = SC_Ag_Render_Access.access_for_create_event(request, primary)
        has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
        
        #If there is create access while update access is restricted from admin then override the create access
        if not has_access_for_sc_ag_updates and has_access:
            has_access = False
        # if (request.META.get('HTTP_REFERER') == 
        if has_access:
            get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
            is_branch = False
            sc_ag=PortData.get_all_sc_ag(request=request)
            inter_branch_collaboration_options=Branch.load_all_inter_branch_collaboration_options()
            context={
                'user_data':user_data,
                'inter_branch_collaboration_options':inter_branch_collaboration_options,
                'all_sc_ag':sc_ag,
                'is_branch':is_branch,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
            }
            if request.method=="POST":
                if(request.POST.get('next')):
                    inter_branch_collaboration_list=request.POST.getlist('inter_branch_collaboration')
                    intra_branch_collaboration=request.POST['intra_branch_collaboration']
                    
                    if(Branch.register_event_page2(
                        inter_branch_collaboration_list=inter_branch_collaboration_list,
                        intra_branch_collaboration=intra_branch_collaboration,
                        event_id=event_id)):
                        return redirect('chapters_and_affinity_group:event_creation_form3',primary,event_id)
                    else:
                        messages.info(request,"Database Error Occured! Please try again later.")

                elif(request.POST.get('cancel')):
                    return redirect('chapters_and_affinity_group:event_control_homepage',primary)


            return render(request,'Events/event_creation_form2.html',context)
        else:
            return render(request, 'access_denied.html', { 'all_sc_ag':sc_ag })
        
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
@login_required
@member_login_permission
def event_creation_form_page3(request,primary,event_id):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        has_access = SC_Ag_Render_Access.access_for_create_event(request, primary)
        has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
        
        #If there is create access while update access is restricted from admin then override the create access
        if not has_access_for_sc_ag_updates and has_access:
            has_access = False

        if has_access:
            get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
            is_branch=False
            sc_ag=PortData.get_all_sc_ag(request=request)
            #loading all venues from the venue list from event management team database
            venues=Events_And_Management_Team.getVenues()
            #loading all the permission criterias from event management team database
            permission_criterias=Events_And_Management_Team.getPermissionCriterias()

            context={
                'user_data':user_data,
                'venues':venues,
                'permission_criterias':permission_criterias,
                'all_sc_ag':sc_ag,
                'is_branch':is_branch,
                'sc_ag_info':get_sc_ag_info,
            }
            if request.method=="POST":
                if request.POST.get('create_event'):
                    #getting the venues for the event
                    venue_list_for_event=request.POST.getlist('event_venues')
                    #getting the permission criterias for the event
                    permission_criterias_list_for_event=request.POST.getlist('permission_criteria')
                    
                    #updating data collected from part3 for the event
                    update_event_details=Branch.register_event_page3(venue_list=venue_list_for_event,permission_criteria_list=permission_criterias_list_for_event,event_id=event_id)
                    #if return value is false show an error message
                    if(update_event_details==False):
                        messages.info(request, "An error Occured! Please Try again!")
                    else:
                        messages.info(request, "New Event Added Succesfully")
                        return redirect('chapters_and_affinity_group:event_control_homepage',primary)

            return render(request,'Events/event_creation_form3.html',context)
        else:
            return render(request, 'access_denied.html', { 'all_sc_ag':sc_ag })
        
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    

@login_required
@member_login_permission
def event_edit_form(request, primary, event_id):

    ''' This function loads the edit page of events '''
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        has_access = SC_Ag_Render_Access.access_for_event_details_edit(request, primary)
        if has_access:
            has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
            show_restriction_banner = False
            if not has_access_for_sc_ag_updates:
                show_restriction_banner = True

            sc_ag=PortData.get_all_sc_ag(request=request)
            get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
            is_branch = False
            is_flagship_event = Branch.is_flagship_event(event_id)
            is_event_published = Branch.load_event_published(event_id)
            is_registraion_fee_true = Branch.is_registration_fee_required(event_id)
            is_featured_event = Branch.is_featured_event(event_id)
            #Get event details from databse
            event_details = Events.objects.get(pk=event_id)

            if(request.method == "POST"):

                if('add_venues' in request.POST):
                    venue = request.POST.get('venue')
                    if(Branch.add_event_venue(venue)):
                        messages.success(request, "Venue created successfully")
                    else:
                        messages.error(request, "Something went wrong while creating the venue")
                    return redirect('chapters_and_affinity_group:event_edit_form', primary, event_id)
                    
                if('update_event' in request.POST):
                    ''' Get data from form and call update function to update event '''

                    form_link = request.POST.get('drive_link_of_event')
                    more_info_link = request.POST.get('more_info_link')
                    publish_event_status = request.POST.get('publish_event')
                    flagship_event_status = request.POST.get('flagship_event')
                    registration_event_status = request.POST.get('registration_fee')
                    event_name=request.POST['event_name']
                    event_description=request.POST['event_description']
                    super_event_id=request.POST.get('super_event')
                    event_type_list = request.POST.getlist('event_type')
                    event_start_date=request.POST['start_date_time']
                    event_end_date=request.POST['end_date_time']
                    inter_branch_collaboration_list=request.POST.getlist('inter_branch_collaboration')
                    intra_branch_collaboration=request.POST['intra_branch_collaboration']
                    venue_list_for_event=request.POST.getlist('event_venues')
                    is_featured = request.POST.get('is_featured_event')

                    #Checking to see of toggle button is on/True or off/False
                    publish_event = Branch.button_status(publish_event_status)
                    flagship_event = Branch.button_status(flagship_event_status)
                    registration_fee = Branch.button_status(registration_event_status)
                    is_featured = Branch.button_status(is_featured)

                    #if there is registration fee then taking the amount from field
                    if registration_fee:
                        registration_fee_amount = request.POST.get('registration_fee_amount')
                    else:
                        registration_fee_amount = event_details.registration_fee_amount

                    #Check if the update request is successful
                    if(Branch.update_event_details(request=request, event_id=event_id, event_name=event_name, event_description=event_description, super_event_id=super_event_id, event_type_list=event_type_list,publish_event = publish_event, event_start_date=event_start_date, event_end_date=event_end_date, inter_branch_collaboration_list=inter_branch_collaboration_list, intra_branch_collaboration=intra_branch_collaboration, venue_list_for_event=venue_list_for_event,
                                                flagship_event = flagship_event,registration_fee = registration_fee,registration_fee_amount=registration_fee_amount,more_info_link=more_info_link,form_link = form_link,is_featured_event=is_featured)):
                        messages.success(request,f"EVENT: {event_name} was Updated successfully")
                        return redirect('chapters_and_affinity_group:event_edit_form',primary, event_id) 
                    else:
                        messages.error(request,"Something went wrong while updating the event!")
                        return redirect('chapters_and_affinity_group:event_edit_form',primary, event_id)
                
                if('delete_event' in request.POST):
                    ''' To delete event from databse '''
                    if(Branch.delete_event(request=request, event_id=event_id)):
                        messages.info(request,f"Event with EVENT ID {event_id} was Removed successfully")
                        return redirect('chapters_and_affinity_group:event_control_homepage',primary)
                    else:
                        messages.error(request,"Something went wrong while removing the event!")
                        return redirect('chapters_and_affinity_group:event_control_homepage',primary)

            form = EventForm({'event_description' : event_details.event_description})

            #loading super/mother event at first and event categories for depending on which group organised the event
            super_events=Branch.load_all_mother_events()
            event_types=Branch.load_all_event_type_for_groups(event_details.event_organiser.primary)

            inter_branch_collaboration_options=Branch.load_all_inter_branch_collaboration_options()

            # Get collaboration details
            interBranchCollaborations=Branch.event_interBranch_Collaborations(event_id=event_id)
            intraBranchCollaborations=Branch.event_IntraBranch_Collaborations(event_id=event_id)
            selected_venues = Branch.get_selected_venues(event_id=event_id)
            # Checking if event has collaborations
            hasCollaboration=False
            if(len(interBranchCollaborations)>0):
                hasCollaboration=True

            interBranchCollaborationsArray = []
            for i in interBranchCollaborations.all():
                interBranchCollaborationsArray.append(i.collaboration_with)

            #loading all venues from the venue list from event management team database
            venues=Events_And_Management_Team.getVenues()

            context={
                'user_data':user_data,
                'all_sc_ag' : sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'primary' : primary,
                'is_branch' : is_branch,
                'event_details' : event_details,
                'event_id' : event_id,
                'form' : form,
                'super_events' : super_events,
                'event_types' : event_types,
                'inter_branch_collaboration_options' : inter_branch_collaboration_options,
                'interBranchCollaborations':interBranchCollaborationsArray,
                'intraBranchCollaborations':intraBranchCollaborations,
                'hasCollaboration' : hasCollaboration,
                'venues' : venues,
                'is_event_published':is_event_published,
                'is_flagship_event':is_flagship_event,
                'is_registration_fee_required':is_registraion_fee_true,
                'selected_venues':selected_venues,
                'is_featured_event':is_featured_event,
                'show_restriction_banner':show_restriction_banner,
                'has_access_for_sc_ag_updates':has_access_for_sc_ag_updates
            }

            return render(request, 'Events/event_edit_form.html', context)
        else:
            return redirect('main_website:event_details', event_id)
        
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
def event_google_calendar(request, primary, event_id):

    try:
        current_user=renderData.LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)

        has_access = SC_Ag_Render_Access.access_for_event_details_edit(request, primary)
        if has_access:
            if(request.method == "POST"):
                if('update_event_gc' in request.POST):
                    google_calendar_publish_event_status = request.POST.get('publish_event_gc')
                    attendeeOption = request.POST.getlist('attendeeList')
                    event_description_for_gc = request.POST.get('event_description_for_gc')
                    add_attendee_names = request.POST.getlist('attendee_name')
                    add_attendee_emails = request.POST.getlist('attendee_email')

                    documents = None
                    if request.FILES.get('document'):
                        documents = request.FILES.getlist('document')

                    publish_event_gc = Branch.button_status(google_calendar_publish_event_status)
                    Branch.update_event_google_calendar(request=request, event_id=event_id, description=event_description_for_gc, publish_event_gc=publish_event_gc, attendeeOption=attendeeOption, add_attendee_names=add_attendee_names, add_attendee_emails=add_attendee_emails, documents=documents)
                if('remove_attachment') in request.POST:
                    attachment_id = request.POST.get('remove_attachment')
                    Branch.delete_attachment(request, attachment_id)

            event = Events.objects.get(id=event_id)
            event_gc_attachments = Google_Calendar_Attachments.objects.filter(event_id=event)
            form = EventFormGC({'event_description_for_gc' : event.event_description_for_gc})
            is_event_published_gc = event.publish_in_google_calendar
            additional_attendees = event.additional_attendees
            recruitment_sessions=PRT_Data.getAllRecruitmentSessions()       
            if event.selected_attendee_list:
                selected_attendee_list = event.selected_attendee_list.split(',')
                selected_attendee_list_for_recruits = [re.findall(r'\d+', item)[0] for item in selected_attendee_list if re.findall(r'\d+', item)]
            else:
                selected_attendee_list = None
                selected_attendee_list_for_recruits = None


            context = {
                'is_branch':False,
                'primary' : primary,
                'user_data':user_data,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'event':event,
                'has_access_for_sc_ag_updates':True,
                'is_event_published_gc':is_event_published_gc,
                'event_id':event_id,
                'form':form,
                'event_gc_attachments':event_gc_attachments,
                'additional_attendees':additional_attendees,
                'recruitment_sessions':recruitment_sessions,
                'selected_attendee_list':selected_attendee_list,
                'selected_attendee_list_for_recruits':selected_attendee_list_for_recruits
            }

            return render(request, 'Events/event_edit_google_calendar.html', context)
        else:
            return render(request, 'access_denied.html', { 'all_sc_ag':sc_ag })
    
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required  
@member_login_permission  
def event_edit_media_form_tab(request, primary, event_id):
    ''' This function loads the media tab page of events '''

    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        has_access = SC_Ag_Render_Access.access_for_event_details_edit(request, primary)
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        #Get event details from databse
        event_details = Events.objects.get(pk=event_id)
        if(has_access):
            has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
            show_restriction_banner = False
            if not has_access_for_sc_ag_updates and has_access:
                show_restriction_banner = True

            #Getting media links and images from database. If does not exist then they are set to none
            try:
                media_links = Media_Link.objects.get(event_id = event_details)
            except:
                media_links = None
            media_images = Media_Images.objects.filter(event_id = event_details)
            number_of_uploaded_images = len(media_images)
            

            if request.method == "POST":

                if request.POST.get('save'):

                    #getting all data from page

                    folder_drive_link_for_event_pictures = request.POST.get('drive_link_of_event')
                    folder_drive_link_for_pictures_with_logos = request.POST.get('logo_drive_link_of_event')
                    selected_images = request.FILES.getlist('image')

                    if(MediaTeam.add_links_and_images(folder_drive_link_for_event_pictures,folder_drive_link_for_pictures_with_logos,
                                                selected_images,event_id)):
                        messages.success(request,'Saved Changes!')
                    else:
                        messages.error(request,'Please Fill All Fields Properly!')
                    return redirect("chapters_and_affinity_group:event_edit_media_form_tab", primary, event_id)
                
                if request.POST.get('remove_image'):

                    #When a particular picture is deleted, it gets the image url from the modal

                    image_url = request.POST.get('remove_image')
                    if(MediaTeam.remove_image(image_url,event_id)):
                        messages.success(request,'Saved Changes!')
                    else:
                        messages.error(request,'Something went wrong')
                    return redirect("chapters_and_affinity_group:event_edit_media_form_tab", primary, event_id)
        
            context={
                'user_data':user_data,
                'is_branch' : False,
                'primary' : primary,
                'event_id' : event_id,
                'media_links' : media_links,
                'media_images':media_images,
                'media_url':settings.MEDIA_URL,
                'allowed_image_upload':6-number_of_uploaded_images,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'show_restriction_banner':show_restriction_banner,
                'has_access_for_sc_ag_updates':has_access_for_sc_ag_updates
            }
            return render(request,"Events/event_edit_media_form_tab.html",context)
        else:
            return render(request, 'access_denied.html', { 'all_sc_ag':sc_ag })
        
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def event_edit_graphics_form_tab(request, primary, event_id):

    ''' This function loads the graphics tab page of events '''

     #Initially loading the events whose  links and images were previously uploaded
    #and can be editible

    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        #Get event details from databse
        event_details = Events.objects.get(pk=event_id)
        has_access = SC_Ag_Render_Access.access_for_event_details_edit(request, primary)
        if(has_access):
            has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
            show_restriction_banner = False
            if not has_access_for_sc_ag_updates and has_access:
                show_restriction_banner = True

            #Getting media links and images from database. If does not exist then they are set to none
            try:
                graphics_link = Graphics_Link.objects.get(event_id = event_details)
            except:
                graphics_link = None
            try:
                graphic_banner_image = Graphics_Banner_Image.objects.get(event_id = event_details)
                image_number = 1
            except:
                graphic_banner_image = None
                image_number = 0

            
            if request.method == "POST":

                if request.POST.get('save'):

                    #getting all data from page
                    drive_link_folder = request.POST.get('drive_link_of_graphics')
                    selected_images = request.FILES.get('image')
                    if(GraphicsTeam.add_links_and_images(drive_link_folder,selected_images,event_id)):
                        messages.success(request,'Saved Changes!')
                    else:
                        messages.error(request,'Please Fill All Fields Properly!')
                    return redirect("chapters_and_affinity_group:event_edit_graphics_form_tab", primary, event_id)
                
                if request.POST.get('remove_image'):

                    #When a particular picture is deleted, it gets the image url from the modal

                    image_url = request.POST.get('remove_image')
                    if(GraphicsTeam.remove_image(image_url,event_id)):
                        messages.success(request,'Saved Changes!')
                    else:
                        messages.error(request,'Something went wrong')
                    return redirect("chapters_and_affinity_group:event_edit_graphics_form_tab", primary, event_id)

            context={
                'user_data':user_data,
                'is_branch' : False,
                'primary' : primary,
                'event_id' : event_id,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'graphic_links' : graphics_link,
                'graphics_banner_image':graphic_banner_image,
                'media_url':settings.MEDIA_URL,
                'allowed_image_upload':1-image_number,
                'has_access_for_sc_ag_updates':has_access_for_sc_ag_updates,
                'show_restriction_banner':show_restriction_banner
            }
            return render(request,"Events/event_edit_graphics_form_tab.html",context)
        else:
            return render(request, 'access_denied.html', { 'all_sc_ag':sc_ag })
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
def event_edit_graphics_form_links_sub_tab(request,primary,event_id):

    ''' This function loads the graphics tab page of events '''

     #Initially loading the events whose  links and images were previously uploaded
    #and can be editible

    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        all_graphics_link = GraphicsTeam.get_all_graphics_form_link(event_id)
        #Get event details from databse
        # event_details = Events.objects.get(pk=event_id)
        has_access = SC_Ag_Render_Access.access_for_event_details_edit(request, primary)
        if(has_access):

            if request.POST.get('add_link'):

                    form_link = request.POST.get('graphics_form_link')
                    title =request.POST.get('title')
                    if GraphicsTeam.add_graphics_form_link(event_id,form_link,title):
                        messages.success(request,'Saved Changes!')
                    else:
                        messages.error(request,'Something went wrong')
                    return redirect("chapters_and_affinity_group:event_edit_graphics_form_links_sub_tab",primary,event_id)
            
            if request.POST.get('update_link'):

                    form_link = request.POST.get('form_link')
                    title =request.POST.get('title')
                    pk = request.POST.get('link_pk')
                    if GraphicsTeam.update_graphics_form_link(form_link,title,pk):
                        messages.success(request,'Updated Successfully!')
                    else:
                        messages.error(request,'Something went wrong')
                    return redirect("chapters_and_affinity_group:event_edit_graphics_form_links_sub_tab",primary,event_id)

            if request.POST.get('remove_form_link'):

                    id = request.POST.get('remove_link')
                    if GraphicsTeam.remove_graphics_form_link(id):
                        messages.success(request,'Deleted Successfully!')
                    else:
                        messages.error(request,'Something went wrong')
                    return redirect("chapters_and_affinity_group:event_edit_graphics_form_links_sub_tab",primary,event_id)

            context={
                'user_data':user_data,
                'is_branch' : False,
                'primary' : primary,
                'event_id' : event_id,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'all_graphics_link':all_graphics_link,

            }
            return render(request,"Events/event_edit_graphics_form_links_sub_tab.html",context)
        else:
            return render(request, 'access_denied.html', { 'all_sc_ag':sc_ag })
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def event_edit_content_form_tab(request,primary,event_id):

    ''' This function loads the content tab page of events '''

    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        #Get event details from databse
        # event_details = Events.objects.get(pk=event_id)
        has_access = SC_Ag_Render_Access.access_for_event_details_edit(request, primary)
        if(has_access):
            has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)
            show_restriction_banner = False
            if not has_access_for_sc_ag_updates and has_access:
                show_restriction_banner = True

            all_notes_content = ContentWritingTeam.load_note_content(event_id)
            form = Content_Form()
            if(request.method == "POST"):               
                if 'add_note' in request.POST:
                    
                    #when the add button for submitting new note is clicked
                    title = request.POST['title']
                    note = request.POST['caption']

                    if ContentWritingTeam.creating_note(title,note,event_id):
                        messages.success(request,"Note created successfully!")
                    else:
                        messages.error(request,"Error occured! Please try again later.")

                    return redirect("chapters_and_affinity_group:event_edit_content_form_tab", primary, event_id)

                if 'remove' in request.POST:
                    id = request.POST.get('remove_note')
                    if ContentWritingTeam.remove_note(id):
                        messages.success(request,"Note deleted successfully!")
                    else:
                        messages.error(request,"Error occured! Please try again later.")
                    return redirect("chapters_and_affinity_group:event_edit_content_form_tab", primary, event_id)  

                if 'update_note' in request.POST:
                    print(request.POST)
                    id = request.POST['update_note']
                    title = request.POST['title']
                    note = request.POST['caption']
                    if(ContentWritingTeam.update_note(id, title, note)):
                        messages.success(request,"Note updated successfully!")
                    else:
                        messages.error(request,"Error occured! Please try again later.")
                    return redirect("chapters_and_affinity_group:event_edit_content_form_tab", primary, event_id)
                
                if('save' in request.POST):
                    event_description = request.POST['event_description']
                    if('drive_link_of_documents' in request.POST):
                        drive_link = request.POST['drive_link_of_documents']
                        success = ContentWritingTeam.update_event_details(event_id=event_id, event_description=event_description, drive_link=drive_link)
                    else:
                        success = ContentWritingTeam.update_event_details(event_id=event_id, event_description=event_description)

                    if(success):
                        messages.success(request,"Event details updated successfully!")
                    else:
                        messages.error(request,"Error occured! Please try again later.")

                    if(len(request.FILES.getlist('document')) > 0):
                        file_list = request.FILES.getlist('document')
                        success2 = ContentWritingTeam.upload_files(event_id=event_id, file_list=file_list)
                        if(success2):
                            messages.success(request,"Files uploaded successfully!")
                        else:
                            messages.error(request,"Error occured while uploading files! Please try again later.")
                            
                    return redirect("chapters_and_affinity_group:event_edit_content_form_tab", primary, event_id)
                
                if('remove2' in request.POST):
                    id = request.POST.get('remove_doc')
                    if ContentWritingTeam.delete_file(id):
                        messages.success(request,"File deleted successfully!")
                    else:
                        messages.error(request,"Error occured! Please try again later.")
                    return redirect("chapters_and_affinity_group:event_edit_content_form_tab", primary, event_id)
                
            event_details = Events.objects.get(id=event_id)
            form2 = EventForm({'event_description' : event_details.event_description})
            try:
                documents_link = Content_Team_Documents_Link.objects.get(event_id = event_details)
            except:
                documents_link = None

            documents = Content_Team_Document.objects.filter(event_id=event_id)   

            context={
                'user_data':user_data,
                'is_branch' : False,
                'primary' : primary,
                'event_id' : event_id,
                'form_adding_note':form,
                'all_notes_content':all_notes_content,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'documents' : documents,
                'media_url' : settings.MEDIA_URL,
                'event_details' : event_details,
                'description_form' : form2,
                'drive_link_of_documents' : documents_link,
                'show_restriction_banner':show_restriction_banner,
                'has_access_for_sc_ag_updates':has_access_for_sc_ag_updates
            }
            return render(request,"Events/event_edit_content_and_publications_form_tab_sc_ag.html",context)
        else:
            return render(request, 'access_denied.html', { 'all_sc_ag':sc_ag })
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
def event_edit_budget_form_tab(request, primary, event_id):

    try:
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        current_user=renderData.LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        
        has_access = SC_Ag_Render_Access.access_for_sc_ag_budget(request, event_id, primary)

        if has_access != 'Restricted':
            if request.method == "POST":
                cst_item = request.POST.getlist('cst_item[]')
                cst_quantity = request.POST.getlist('cst_quantity[]')
                cst_upc_bdt = request.POST.getlist('cst_upc_bdt[]')
                cst_total = request.POST.getlist('cst_total[]')

                rev_item = request.POST.getlist('rev_item[]')
                rev_quantity = request.POST.getlist('rev_quantity[]')
                rev_upc_bdt = request.POST.getlist('rev_upc_bdt[]')
                rev_total = request.POST.getlist('rev_total[]')

                saved_rate = request.POST.get('saved_rate')
                show_usd_rates = request.POST.get('show_usd_rates')
                
                if BudgetSheet.objects.filter(event=event_id).count() == 0:
                    if Sc_Ag.create_budget(request, primary, event_id, cst_item, cst_quantity, cst_upc_bdt, cst_total, rev_item, rev_quantity, rev_upc_bdt, rev_total):
                        messages.success(request, 'Budget created successfully!')
                    else:
                        messages.warning(request, 'Could not create budget!')
                else:
                    budget_sheet_id = BudgetSheet.objects.get(event=event_id).pk
                    if Sc_Ag.edit_budget(budget_sheet_id, cst_item, cst_quantity, cst_upc_bdt, cst_total, rev_item, rev_quantity, rev_upc_bdt, rev_total, saved_rate, show_usd_rates):
                        messages.success(request, 'Budget updated successfully!')
                    else:
                        messages.warning(request, 'Could not update budget!')
                
                return redirect('chapters_and_affinity_group:event_edit_budget_form_tab', primary, event_id)
                
            if BudgetSheet.objects.filter(event=event_id).count() > 0:
                budget_sheet = BudgetSheet.objects.get(event=event_id)
            else:
                budget_sheet = None
            
            deficit = 0.0
            surplus = 0.0

            usd_rate = None
            if budget_sheet:

                if budget_sheet.total_cost > budget_sheet.total_revenue:
                    deficit = budget_sheet.total_revenue - budget_sheet.total_cost
                elif budget_sheet.total_cost < budget_sheet.total_revenue:
                    surplus = budget_sheet.total_revenue - budget_sheet.total_cost
                
                currency_data_response = requests.get('https://latest.currency-api.pages.dev/v1/currencies/usd.min.json')
                if(currency_data_response.status_code==200):
                    # if response is okay then load data
                    usd_rate = json.loads(currency_data_response.text)['usd']['bdt']
                else:
                    usd_rate = None

            event = Events.objects.get(id=event_id)

            context = {
                'is_branch' : False,
                'primary' : primary,
                'event_id' : event_id,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'user_data':user_data,
                'budget_sheet':budget_sheet,
                'access_type': has_access if has_access == 'ViewOnly' else 'Edit',
                'deficit':deficit,
                'surplus':surplus,
                'event':event,
                'usd_rate':usd_rate
            }

            return render(request,"Events/event_edit_budget_form_tab.html", context)
        else:
            return render(request,"access_denied2.html", {'all_sc_ag':sc_ag ,'user_data':user_data,})

    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

    
@login_required
@member_login_permission
@xframe_options_exempt
def event_preview(request, primary, event_id):
    ''' This function displays a preview of an event regardless of it's published status '''

    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file

        has_access = SC_Ag_Render_Access.access_for_event_details_edit(request, primary)
        if(has_access):
            event = Events.objects.get(id=event_id)
            get_inter_branch_collab=InterBranchCollaborations.objects.filter(event_id=event.pk)
            get_intra_branch_collab=IntraBranchCollaborations.objects.filter(event_id=event.pk).first()
            
            has_interbranch_collab=False
            has_intrabranch_collab=False
            
            if(len(get_inter_branch_collab) > 0):
                has_interbranch_collab=True
            if(get_intra_branch_collab is not None):
                has_intrabranch_collab=True
                
            event_banner_image = HomepageItems.load_event_banner_image(event_id=event_id)
            event_gallery_images = HomepageItems.load_event_gallery_images(event_id=event_id)

            context = {
                'user_data':user_data,
                'is_branch' : False,
                'event' : event,
                'media_url':settings.MEDIA_URL,
                'event_banner_image' : event_banner_image,
                'event_gallery_images' : event_gallery_images,
                'has_interbranch_collab':has_interbranch_collab,
                'has_intrabranch_collab':has_intrabranch_collab,
                'inter_collaborations':get_inter_branch_collab,
                'intra_collab':get_intra_branch_collab,
            }

            return render(request, 'Events/event_description_main.html', context)
        else:
            return render(request, 'access_denied.html')
    
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    

@login_required
@member_login_permission
def manage_main_website(request, primary):

    '''This view function loads the portals page for managing main website of socities
        and affinity group'''

    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
  
        has_access = SC_Ag_Render_Access.access_for_manage_web(request, primary)
        if(has_access):
            has_access_for_sc_ag_updates = SC_Ag_Render_Access.access_for_sc_ag_updates(request=request)

            show_restriction_banner = False
            #If access restricted from admin then show banner
            if not has_access_for_sc_ag_updates:
                show_restriction_banner = True

            if request.method == "POST":
                #if save button is clicked then saving the details user entered
                if request.POST.get('save'):

                    about_image = request.FILES.get('logo')
                    about_details = request.POST.get('about_details')
                    background_image =  request.FILES.get('background_image')
                    mission_description = request.POST.get('mission_details')
                    mission_image =  request.FILES.get('mission_picture')
                    vision_description = request.POST.get('vision_details')
                    vision_picture =  request.FILES.get('vision_picture')
                    what_is_this_description = request.POST.get('what_is_this_details')
                    why_join_it = request.POST.get('why_join_this_details')
                    what_activites_it_has = request.POST.get('what_activities_does_this_do_details')
                    how_to_join = request.POST.get('how_to_join_this_details')
                    short_form = request.POST.get('short_form')
                    short_form_alternative_details = request.POST.get('short_form_alternative')
                    primary_color_code_details = request.POST.get('primary_color_code')
                    secondary_color_code_details = request.POST.get('secondary_color_code')
                    text_color_code_details = request.POST.get('text_color_code')
                    pageTitle_details = request.POST.get('pageTitle')
                    secondParagraph_details = request.POST.get('secondParagraph')
                    email = request.POST.get('email')
                    facebook_link = request.POST.get('facebook_link')
                    mission_vision_color_code_details = request.POST.get('mission_vision_color_code')

                    #checking to see if no picture is uploaded by user, if so then if picture is already present in database
                    #then updating it with saved value to prevent data loss. Otherwise it is None
                    if about_image == None:
                        about_image = get_sc_ag_info.logo
                    if background_image == None:
                        background_image = get_sc_ag_info.background_image
                    if vision_picture == None:
                        vision_picture = get_sc_ag_info.vision_picture
                    if mission_image == None:
                        mission_image = get_sc_ag_info.mission_picture

                    #passing the fields data to the function to check length before saving
                    if Sc_Ag.checking_length(request,about_details,mission_description,vision_description,what_is_this_description,
                               why_join_it,what_activites_it_has,how_to_join):
                        messages.error(request,"Please ensure your word limit is within 1500 and you have filled out all descriptions")
                        return redirect("chapters_and_affinity_group:manage_main_website",primary)
                    #passing the fields data to save the data in the database
                    if Sc_Ag.main_website_info(request,primary,about_details,about_image,background_image,
                                    mission_description,mission_image,vision_description,vision_picture,
                                    what_is_this_description,why_join_it,what_activites_it_has,how_to_join,
                                    short_form,short_form_alternative_details,primary_color_code_details,secondary_color_code_details,
                                    text_color_code_details,pageTitle_details,secondParagraph_details,email,facebook_link,mission_vision_color_code_details):
                        
                            messages.success(request,"Saved Changes Successfully!")
                    else:
                        messages.error(request,"Error while saving changes.")
                    return redirect("chapters_and_affinity_group:manage_main_website",primary)
                
                if request.POST.get('remove'):
                    #when user wants to remove any picture from the main website of sc_ag through the portal
                    #getting the image path
                    image = request.POST.get('image_delete')
                    #getting the image id
                    image_id = request.POST.get('image_id')
                    #passing them to the delete function, if deleted successfully, success message pops else
                    #error message
                    if Sc_Ag.delete_image(request,primary,image_id,image):
                        messages.success(request,"Deleted Successfully!")
                    else:
                        messages.error(request,"Error while deleting picture.")
                    return redirect("chapters_and_affinity_group:manage_main_website",primary)


            context={
                'user_data':user_data,
                'is_branch' : False,
                'primary' : primary,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'media_url':settings.MEDIA_URL,
                'has_access_for_sc_ag_updates':has_access_for_sc_ag_updates,
                'show_restriction_banner':show_restriction_banner
            }

            return render(request,"Main Web Form/portal_form.html",context)
        else:
            return render(request, 'access_denied.html', { 'all_sc_ag':sc_ag })

    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
@xframe_options_exempt
def manage_main_website_preview(request,primary):
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        #getting object of the particular society/affinity
        society = Chapters_Society_and_Affinity_Groups.objects.get(primary = primary)
        #getting featured events of the particular society/affinity 
        featured_events = HomepageItems.get_featured_events_for_societies(primary)

        #getting faculty member
        faculty_advisor = HomepageItems.get_faculty_advisor_for_society(request,primary)
        #getting eb members for the particular society/affinity
        eb_members = HomepageItems.get_eb_members_for_society(request,primary)

        context={
            'user_data':user_data,
            'is_live':False, #This disable the header and footer of the page along with wavy for previewing
            'society':society,
            #'branch_teams':PortData.get_teams_of_sc_ag_with_id(request=request,sc_ag_primary=1), #loading all the teams of Branch
            'media_url':settings.MEDIA_URL,
            'featured_events':featured_events,
            'faculty_advisor':faculty_advisor,
            'eb_members':eb_members,
            'page_title':society.page_title,
            'page_subtitle':society.secondary_paragraph
        }

        return render(request,'Society_AG/sc_ag.html',context=context)
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def feedbacks(request,primary):

    '''This view function loads the feedback page for the particular societies and affinity
        groups'''
    
    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        #rendering all the data to be loaded on the page
        sc_ag=PortData.get_all_sc_ag(request=request)
        get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
        has_access = SC_Ag_Render_Access.access_for_manage_web(request, primary)
        #getting all the feedbacks for the particular societies and affinity groups
        all_feedbacks = Sc_Ag.get_all_feedbacks(request,primary)
        if(has_access):
            
            if request.method=="POST":
                #when user hits submit button to changes status of responded fields
                if request.POST.get('reponded'):
                    #getting all the list of boolean fields that were changed
                    respond = request.POST.getlist('responded_id')
                    #passing the list to the updating funtion to change boolean values
                    if Sc_Ag.set_feedback_status(respond,primary):
                        messages.success(request,'Feedback status updated successfully.')
                    else:
                        messages.error(request,'Feedback status could not be updated.')
                    return redirect("chapters_and_affinity_group:feedbacks",primary)
        
            context={
                    'user_data':user_data,
                    'is_branch' : False,
                    'primary' : primary,
                    'all_sc_ag':sc_ag,
                    'sc_ag_info':get_sc_ag_info,
                    'media_url':settings.MEDIA_URL,
                    'all_feedbacks':all_feedbacks,

            }
            return render(request,"FeedBack/feedback.html",context)
        else:
            return render(request, 'access_denied.html', { 'all_sc_ag':sc_ag })
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def event_feedback(request, primary, event_id):

    try:
        current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        sc_ag=PortData.get_all_sc_ag(request=request)
        has_access = SC_Ag_Render_Access.access_for_event_details_edit(request, primary)
        if has_access:
            get_sc_ag_info=SC_AG_Info.get_sc_ag_details(request,primary)
            event_feedbacks = Branch.get_all_feedbacks(event_id=event_id)

            context = {
                'user_data':user_data,
                'all_sc_ag':sc_ag,
                'sc_ag_info':get_sc_ag_info,
                'primary':primary,
                'is_branch':False, 
                'event_id':event_id, 
                'event_feedbacks':event_feedbacks
            }

            return render(request,'Events/event_feedbacks.html', context)
        else:
            return render(request,'access_denied.html', { 'all_sc_ag':sc_ag })
        
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
def generateExcelSheet_events_by_year_sc_ag(request,primary,year):

    '''This method generates the excel files for The events according to the year selected'''

    try:
        society = Chapters_Society_and_Affinity_Groups.objects.get(primary = primary)
        #Loading Access Permission
        user=request.user
        #need to give acccess for downloading this file
        has_access=SC_Ag_Render_Access.get_sc_ag_common_access(request,user.username)
        if has_access:
            date=datetime.now()
            response = HttpResponse(
                content_type='application/ms-excel')  # eclaring content type for the excel files
            response['Content-Disposition'] = f'attachment; filename={society.short_form}_Events_{year} - ' +\
                str(date.strftime('%m/%d/%Y')) + \
                '.xls'  # making files downloadable with name of session and timestamp
            # adding encoding to the workbook
            workBook = xlwt.Workbook(encoding='utf-8')
            # opening an worksheet to work with the columns
            workSheet = workBook.add_sheet(f'Events List of {year}')

            # generating the first row
            row_num = 0
            font_style = xlwt.XFStyle()
            font_style.font.bold = True

            # Defining columns that will stay in the first row
            columns = ['SL','Event Name','Event Date', 'Organiser', 'Collaborations','Event Type','Venue']

            # Defining first column
            column_widths = [1000,4000, 6000, 18000, 18000, 6000,6000]
            for col, width in enumerate(column_widths):
                workSheet.col(col).width = width


            for column in range(len(columns)):
                workSheet.write(row_num, column, columns[column], font_style)

            # reverting font style to default
            font_style = xlwt.XFStyle()

            # Center alignment style
            center_alignment = xlwt.easyxf('align: horiz center')
            # Word wrap style
            word_wrap_style = xlwt.easyxf('alignment: wrap True')

            events= Branch.load_all_inter_branch_collaborations_with_events_yearly(year,primary)
            sl_num = 0
            for event,collaborations in events.items():
                row_num += 1
                sl_num += 1
                workSheet.write(row_num,0 , sl_num,  center_alignment)
                workSheet.write(row_num,1 , event.event_name,  center_alignment)
                if event.event_date:
                    workSheet.write(row_num,2 , event.event_date.strftime('%Y-%m-%d'),  center_alignment)
                else:
                    workSheet.write(row_num,2 , event.start_date.strftime('%Y-%m-%d'),  center_alignment)
                workSheet.write(row_num,3 , event.event_organiser.group_name,  center_alignment)
                collaborations_text = ""
                for collabs in collaborations:
                    collaborations_text += collabs + '\n'
                workSheet.write(row_num, 4, collaborations_text, word_wrap_style) 
                categories = ""   
                for event_type in event.event_type.all():
                    categories+=event_type.event_category + '\n'  
                workSheet.write(row_num, 5, categories, word_wrap_style)
                venue_list = Branch.get_selected_venues(event.pk)
                venues=""
                for venue in venue_list:
                    venues += venue + '\n'
                workSheet.write(row_num, 6, venues, word_wrap_style)
                    
            workBook.save(response)
            return (response)
        else:
            return render(request,'access_denied2.html')
        
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)