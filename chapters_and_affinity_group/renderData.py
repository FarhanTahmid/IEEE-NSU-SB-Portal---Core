from django.contrib import messages
from .models import SC_AG_Members
from users.models import Members,Panel_Members
from port.models import Panels,Chapters_Society_and_Affinity_Groups,Teams,Roles_and_Position
import logging
from system_administration.system_error_handling import ErrorHandling
import traceback
from datetime import datetime

class Sc_Ag:
    logger=logging.getLogger(__name__)
        
    def add_insb_members_to_sc_ag(request,sc_ag_primary,ieee_id_list,team_pk,position_id):
        '''This method adds an existing Member Registered in INSB to a SC or AG'''
        get_sc_ag=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary)
        count=0
        try:
            for ieee_id in ieee_id_list:
                if(SC_AG_Members.objects.filter(sc_ag=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary),member=Members.objects.get(ieee_id=ieee_id)).exists()):
                    messages.info(request,f"Member with IEEE ID: {ieee_id} already exists in Database")
                else:
                    new_sc_ag_member=SC_AG_Members.objects.create(sc_ag=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary)
                                                                ,member=Members.objects.get(ieee_id=ieee_id))
                    if team_pk is not None:
                        new_sc_ag_member.team=Teams.objects.get(pk=team_pk)
                    if position_id is not None:
                        new_sc_ag_member.position=Roles_and_Position.objects.get(id=position_id)
                    new_sc_ag_member.save()
                    count+=1
            messages.success(request,f"{count} new members were added to the Member List of {get_sc_ag.group_name} ")
            return True
        except Exception as e:
            Sc_Ag.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            return False
    
    
    def create_new_panel_of_sc_ag(request,sc_ag_primary,tenure_year,current_check,panel_start_time,panel_end_time):
        try:
            new_sc_ag_panel=Panels.objects.create(year=tenure_year,creation_time=panel_start_time,current=current_check,panel_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary),panel_end_time=panel_end_time)
            new_sc_ag_panel.save()
        except Exception as e:
            Sc_Ag.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            return False
        
    def delete_ac_ag_panel(request,panel_id):
        '''This function deletes the panels and turn the Member of SC AG into a General Member and Team to None'''
        get_panel=Panels.objects.get(pk=panel_id)
        pass
    
    def add_sc_ag_members_to_panel(request,panel_id,memberList,position_id,team,sc_ag_primary):
        '''This method adds Members from SC_AG to their panels'''
        try:
            count=0
            for i in memberList:
                # check if the member already exists in the panel
                check_existing_member=Panel_Members.objects.filter(tenure=Panels.objects.get(id=panel_id),member=Members.objects.get(ieee_id=i))
                # get the Member from SC AG Database as well
                member_in_sc_ag=SC_AG_Members.objects.filter(sc_ag=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary),member=Members.objects.get(ieee_id=i))
                
                if(check_existing_member.exists()):
                    # if exists, then update the members position with new Team and Positions
                    check_existing_member.update(position=Roles_and_Position.objects.get(id=position_id))
                    # Update members position and team in SC AG members database as well
                    member_in_sc_ag.update(position=Roles_and_Position.objects.get(id=position_id))
                    if team is None:
                        check_existing_member.update(team=None)
                        member_in_sc_ag.update(team=None)
                    else:
                        check_existing_member.update(team=Teams.objects.get(primary=team))
                        member_in_sc_ag.update(team=Teams.objects.get(primary=team))
                    messages.info(request,f"Member {i} already existed in the panel. Their Position and Team were updated!")
                else:
                    # Now create a new panel Member for the Panel and SC-AG
                    if(team is None):
                        # if team is not passed, it stays none
                        new_paneL_member=Panel_Members.objects.create(
                            tenure=Panels.objects.get(id=panel_id),
                            member=Members.objects.get(ieee_id=i),
                            position=Roles_and_Position.objects.get(id=position_id),
                            team=None
                        )
                        new_paneL_member.save()
                        member_in_sc_ag.update(position=Roles_and_Position.objects.get(id=position_id),team=None)
                        count+=1
                    else:
                        # create new panel Member with Team info if team info is given
                        new_paneL_member=Panel_Members.objects.create(
                            tenure=Panels.objects.get(id=panel_id),
                            member=Members.objects.get(ieee_id=i),
                            position=Roles_and_Position.objects.get(id=position_id),
                            team=Teams.objects.get(primary=team)
                        )
                        new_paneL_member.save()
                        member_in_sc_ag.update(position=Roles_and_Position.objects.get(id=position_id),team=Teams.objects.get(primary=team))
                        count+=1
            if(count>1):
                # if multiple members were added then show this message
                messages.success(request,f"{count} new members were added to the panel")              
            elif(count==1):
                # else show a singular message
                messages.success(request,f"{count} new member was added to the panel")              
            return True
        except Exception as e:
            Sc_Ag.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            return False
    
    def remove_sc_ag_member_from_panel(request,panel_id,member_ieee_id,sc_ag_primary):
        """ This Method removes Members from SC_AG  Panels and also makes their Position and Team in SC Ag member table None"""
        member_in_panel=Panel_Members.objects.filter(tenure=Panels.objects.get(pk=panel_id),member=Members.objects.get(ieee_id=member_ieee_id))
        for i in member_in_panel:
            i.delete()
            member_in_sc_ag=SC_AG_Members.objects.filter(sc_ag=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary),member=Members.objects.get(ieee_id=member_ieee_id))
            member_in_sc_ag.update(team=None,position=None)
            messages.error(request,f"{i.member.name} was removed from the panel!")
        return True
        