from django.http import HttpResponseBadRequest
from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from content_writing_and_publications_team.manage_access import CWPTeam_Render_Access
from port.renderData import PortData
from users.models import Members
from central_branch.renderData import Branch
from port.models import Roles_and_Position
from django.contrib import messages
from .renderData import ContentWritingTeam
from system_administration.models import CWP_Data_Access
from system_administration.system_error_handling import ErrorHandling
import logging
from datetime import datetime
import traceback


logger=logging.getLogger(__name__)
# Create your views here.

@login_required
def homepage(request):
    return render(request,"Homepage/content_homepage.html")

@login_required
def manage_team(request):

    '''This function loads the manage team page for content writing and publications team and is accessable
    by the co-ordinatior only, unless the co-ordinators gives access to others as well'''

    has_access = CWPTeam_Render_Access.get_common_access(request)
    if has_access:
        data_access = ContentWritingTeam.load_manage_team_access()
        team_members = ContentWritingTeam.load_team_members()
        #load all position for insb members
        position=Branch.load_roles_and_positions()

        # Excluding position of EB, Faculty and SC-AG members
        for i in position:
            if(i.is_eb_member or i.is_faculty or i.is_sc_ag_eb_member):
                position=position.exclude(pk=i.pk)

        #load all insb members
        all_insb_members=Members.objects.all()
        #load all current panel members
        current_panel_members = Branch.load_current_panel_members()

        if request.method == "POST":
            if (request.POST.get('add_member_to_team')):
                #get selected members
                members_to_add=request.POST.getlist('member_select1')
                #get position
                position=request.POST.get('position')
                for member in members_to_add:
                    ContentWritingTeam.add_member_to_team(member,position)
                return redirect('content_writing_and_publications_team:manage_team')
            
            if (request.POST.get('remove_member')):
                '''To remove member from team table'''
                try:
                    Members.objects.filter(ieee_id=request.POST['remove_ieee_id']).update(team=None,position=Roles_and_Position.objects.get(id=13))
                    try:
                        CWP_Data_Access.objects.filter(ieee_id=request.POST['remove_ieee_id']).delete()
                    except CWP_Data_Access.DoesNotExist:
                        return redirect('content_writing_and_publications_team:manage_team')
                    return redirect('content_writing_and_publications_team:manage_team')
                except:
                    pass
            if request.POST.get('access_update'):
                manage_team_access = False
                if(request.POST.get('manage_team_access')):
                    manage_team_access=True
                event_access=False
                if(request.POST.get('event_access')):
                    event_access=True
                ieee_id=request.POST['access_ieee_id']
                if (ContentWritingTeam.cwp_manage_team_access_modifications(manage_team_access, event_access, ieee_id)):
                    permission_updated_for=Members.objects.get(ieee_id=ieee_id)
                    messages.info(request,f"Permission Details Was Updated for {permission_updated_for.name}")
                else:
                    messages.info(request,f"Something Went Wrong! Please Contact System Administrator about this issue")
            
            if request.POST.get('access_remove'):
                '''To remove record from data access table'''
                
                ieeeId=request.POST['access_ieee_id']
                if(ContentWritingTeam.remove_member_from_manage_team_access(ieee_id=ieeeId)):
                    messages.info(request,"Removed member from Managing Team")
                    return redirect('content_writing_and_publications_team:manage_team')
                else:
                    messages.info(request,"Something went wrong!")

            if request.POST.get('update_data_access_member'):
                
                new_data_access_member_list=request.POST.getlist('member_select')
                
                if(len(new_data_access_member_list)>0):
                    for ieeeID in new_data_access_member_list:
                        if(ContentWritingTeam.add_member_to_manage_team_access(ieeeID)=="exists"):
                            messages.info(request,f"The member with IEEE Id: {ieeeID} already exists in the Data Access Table")
                        elif(ContentWritingTeam.add_member_to_manage_team_access(ieeeID)==False):
                            messages.info(request,"Something Went wrong! Please try again")
                        elif(ContentWritingTeam.add_member_to_manage_team_access(ieeeID)==True):
                            messages.info(request,f"Member with {ieeeID} was added to the team table!")
                            return redirect('content_writing_and_publications_team:manage_team')

        context={
            'data_access':data_access,
            'members':team_members,
            'insb_members':all_insb_members,
            'current_panel_members':current_panel_members,
            'positions':position,
            
        }
        return render(request,"content_writing_and_publications_team/manage_team.html",context=context)
    else:
        return render(request,"content_writing_and_publications_team/access_denied.html")

@login_required
def event_page(request):

    '''Only events organised by INSB would be shown on the event page of Content and Publications Team
       So, only those events are being retrieved from database'''
    
    insb_organised_events = Branch.load_insb_organised_events()

    context = {'events_of_insb_only':insb_organised_events,}
    

    return render(request,"Events/content_team_events_homepage.html",context)


@login_required
def event_form(request,event_id):

    try:
        sc_ag=PortData.get_all_sc_ag(request=request)
        has_access = CWPTeam_Render_Access.access_for_events(request)

        if has_access:
            if(request.method == "POST"):
                # print(request.POST.get('caption'))
                print(request.POST.get('LOL'))
            
            context = {
                'all_sc_ag':sc_ag,
            }

            return render(request,"Events/content_team_event_form.html", context)
        else:
            return redirect('main_website:event_details', event_id)
        
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        # TODO: Make a good error code showing page and show it upon errror
        return HttpResponseBadRequest("Bad Request")
    

@login_required
def event_form_add_notes(request,event_id):

    try:
        sc_ag=PortData.get_all_sc_ag(request=request)
        has_access = CWPTeam_Render_Access.access_for_events(request)

        if has_access:
            if(request.method == "POST"):
                # print(request.POST.get('caption'))
                print(request.POST.get('LOL'))
            
            context = {
                'all_sc_ag':sc_ag,
            }

            return render(request,"Events/content_team_event_form_add_notes.html", context)
        else:
            return redirect('main_website:event_details', event_id)
        
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        # TODO: Make a good error code showing page and show it upon errror
        return HttpResponseBadRequest("Bad Request")

