from .models import Chapters_Society_and_Affinity_Groups,Roles_and_Position,Teams,Panels,VolunteerAwards
from django.contrib import messages
from users.models import Members, Panel_Members,VolunteerAwardRecievers,VolunteerAwards
from datetime import datetime
import sqlite3
import logging
import traceback
from system_administration.system_error_handling import ErrorHandling


class HandleVolunteerAwards:
    '''Handles all the activities related to volunteer awards'''
    logger=logging.getLogger(__name__)

    def create_new_award(request,**kwargs):
        try:
            # create new award
            get_the_latest_ranked_award=VolunteerAwards.objects.filter().first()
            if(get_the_latest_ranked_award is not None):
                new_rank=get_the_latest_ranked_award.rank_of_awards+5
            else:
                new_rank=0
            new_award=VolunteerAwards.objects.create(
                volunteer_award_name=kwargs['volunteer_award_name'],
                panel=Panels.objects.get(pk=kwargs['panel_pk']),
                award_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=kwargs['sc_ag_primary']),
                rank_of_awards=new_rank
            )
            new_award.save()
            messages.success(request,f"New Award: {kwargs['volunteer_award_name']} was created!")
            return True            
            
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.info(request,'Something went wrong while creating new award!')
            return False
    
    def load_awards_for_panels(request,panel_pk):
        try:
            load_all_awards=VolunteerAwards.objects.filter(panel=Panels.objects.get(pk=panel_pk))
            return load_all_awards
        
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.info(request,'Something went wrong while loading awards!')
            return False
    
    def load_award_details(request,award_pk):
        try:
            get_award=VolunteerAwards.objects.get(pk=award_pk)
            return get_award
        
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc() + '\n' + ' url:' + request.build_absolute_uri())
            messages.info(request,'Something went wrong while loading award information!')
            return False
    
    def load_award_winners(request,award_pk):
        try:
            get_award_winners=VolunteerAwardRecievers.objects.filter(award=VolunteerAwards.objects.get(pk=award_pk))
            if(get_award_winners is not None):
                return get_award_winners
            else:
                return False
        
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc() + '\n' + ' url:' + request.build_absolute_uri())
            messages.info(request,'Something went wrong while loading award winners!')
            return False
    
    def add_award_winners(request,award_pk,selected_members,contribution):
        try:
            for i in selected_members:
                if(VolunteerAwardRecievers.objects.filter(award_reciever=Members.objects.get(ieee_id=i),award=VolunteerAwards.objects.get(pk=award_pk)).exists()):
                    messages.info(request,f"IEEE ID: {i} already exists in this award table.")
                else:
                    new_award_winner=VolunteerAwardRecievers.objects.create(
                        award=VolunteerAwards.objects.get(pk=award_pk),
                        award_reciever=Members.objects.get(ieee_id=i),
                        contributions=contribution
                    )
                    new_award_winner.save()
            messages.success(request,f"Award members were updated!")
            return True
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.warning(request,'Something went wrong while adding award winners!')
            return False
    
    def remove_award_winner(request,award_pk,member_ieee_id):
        try:
            get_object=VolunteerAwardRecievers.objects.filter(award=VolunteerAwards.objects.get(pk=award_pk),award_reciever=Members.objects.get(ieee_id=member_ieee_id)).first()
            if(get_object is not None):
                messages.warning(request,f"IEEE ID: {get_object.award_reciever} was removed from the award!")
                get_object.delete()
                return True
            else:
                messages.info(request,"Member doest not exists in awards table!")
                return False
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.warning(request,'Something went wrong while deleting award winners!')
            return False
    
    def update_awards(request,award_pk,award_name):
        try:
            get_object=VolunteerAwards.objects.get(pk=award_pk)
            try:
                get_object.volunteer_award_name=award_name
                get_object.save()
                messages.success(request,"Award was updated!")
                return True
            except VolunteerAwards.DoesNotExist:
                messages.warning(request,"Award does not exist!")
                return False
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.warning(request,'Something went wrong while updating award!')
            return False
    
    def delete_award(request,award_pk):
        try:
            if(award_pk==""):
                print("here")
                messages.warning(request,"Please select an award first!")
                return False
            else:
                try:
                    get_object=VolunteerAwards.objects.get(pk=award_pk)
                    messages.warning(request,f"{get_object.volunteer_award_name} award was deleted!")
                    get_object.delete()
                    return True
                except VolunteerAwards.DoesNotExist:
                    messages.warning(request,"Award does not exist!")
                    return False

        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.warning(request,'Something went wrong while deleting award!')
            return False


class PortData:
    logger=logging.getLogger(__name__)
    
    def get_sc_ag(request,primary):
        '''Returns the details of the SC AG'''
        try:
            return Chapters_Society_and_Affinity_Groups.objects.get(primary=primary)
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.info(request,'Something went wrong fetching the Chapter and Affinity Group')
            return False
    
    def get_all_sc_ag(request):
        '''Returns all the Chapters, Affinity Groups with their Primary. Branch is excluded.'''
        try:
            return Chapters_Society_and_Affinity_Groups.objects.all().exclude(primary=1).order_by('primary') #excluding branch's Primary
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.info(request,'Something went wrong fetching the Chapters and Affinity Groups')
            return False
        
    def get_positions_with_sc_ag_id(request,sc_ag_primary):
        try:
            positions=Roles_and_Position.objects.filter(role_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary)).all().order_by('id','is_faculty','is_eb_member','is_sc_ag_eb_member','is_co_ordinator','is_officer')
            return positions
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"An internal Database error occured loading the Positions!")
            return False
    
    def get_branch_ex_com_from_sc_ag(request):
        '''This method gets all the Chairs of SC AG from current panel'''
        try:
            chairs_of_sc_ag=[]
            # as sc_ag_primary extends from 2-5, if in future any sc ag extends, extend the range
            for i in range(2,6):
                try:
                    get_current_panel_of_sc_ag=Panels.objects.get(current=True,panel_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=i))
                except:
                    continue
                get_panel_members=Panel_Members.objects.filter(tenure=Panels.objects.get(pk=get_current_panel_of_sc_ag.pk))
                if(get_panel_members.exists()):
                    for member in get_panel_members:
                        if(member.position.is_sc_ag_eb_member):
                            if(member.position.role=="Chair"):
                                chairs_of_sc_ag.append(member)
            return chairs_of_sc_ag
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"An internal Database error occured loading the Excom!")
    
    def get_sc_ag_faculty_members(request):
        '''This function returns all the faculties related to sc ag'''
        try:
            faculties_of_sc_ag=[]
            for i in range(2,6):
                try:
                    get_current_panel_of_sc_ag=Panels.objects.get(current=True,panel_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=i))
                except:
                    continue
                get_panel_members=Panel_Members.objects.filter(tenure=Panels.objects.get(pk=get_current_panel_of_sc_ag.pk))
                if(get_panel_members.exists()):
                    for member in get_panel_members:
                        if(member.position.is_sc_ag_eb_member and member.position.is_faculty):
                            faculties_of_sc_ag.append(member)
            return faculties_of_sc_ag
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"An internal Database error occured loading the Faculties of SC AG!")

    def get_branch_ex_com_from_sc_ag_by_year(request,panel_year):
        '''This methods loads SC AG Chairs by year'''
        try:
            chairs_of_sc_ag=[]
            for i in range(2,6):
                try:
                    get_panel_of_sc_ag=Panels.objects.get(year=panel_year,panel_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=i))
                except:
                    continue
                get_panel_members=Panel_Members.objects.filter(tenure=Panels.objects.get(pk=get_panel_of_sc_ag.pk))
                if(get_panel_members.exists()):
                    for member in get_panel_members:
                        if(member.position.is_sc_ag_eb_member):
                            if(member.position.role=="Chair"):
                                chairs_of_sc_ag.append(member)
            return chairs_of_sc_ag
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"An internal Database error occured loading the Excom!")
    
    def get_sc_ag_faculty_by_year(request,panel_year):
        try:
            faculty_of_sc_ag=[]
            for i in range(2,6):
                try:
                    get_panel_of_sc_ag=Panels.objects.get(year=panel_year,panel_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=i))
                except:
                    continue
                get_panel_members=Panel_Members.objects.filter(tenure=Panels.objects.get(pk=get_panel_of_sc_ag.pk))
                if(get_panel_members.exists()):
                    for member in get_panel_members:
                        if(member.position.is_sc_ag_eb_member and member.position.is_faculty):
                            faculty_of_sc_ag.append(member)
            return faculty_of_sc_ag
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"An internal Database error occured loading the Excom!")
                
    def get_all_executive_positions_of_branch(request,sc_ag_primary):
         
        try:
            executive_positions=Roles_and_Position.objects.filter(is_eb_member=True,role_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary)).all().order_by('id')
            return executive_positions
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"An internal Database error occured loading the Positions for Executive Members!")
            return False
    
    def get_all_officer_positions_with_sc_ag_id(request,sc_ag_primary):
        try:
            officer_positions=Roles_and_Position.objects.filter(is_officer=True,role_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary)).all().order_by('id')
            return officer_positions
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"An internal Database error occured loading the Positions for Officer Members!")
            return False
    
    def get_all_volunteer_position_with_sc_ag_id(request,sc_ag_primary):
        try:
            volunteer_positions=Roles_and_Position.objects.filter(is_officer=False,is_eb_member=False,is_sc_ag_eb_member=False,is_co_ordinator=False,is_faculty=False,role_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary)).all().order_by('id')
            return volunteer_positions
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"An internal Database error occured loading the Positions for Volunteer Members!")
            return False
    def get_all_positions_of_everyone(request,sc_ag_primary):
        try:
            all_positions=Roles_and_Position.objects.filter(role_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary))
            return all_positions
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"An internal Database error occured loading all Positions!")
            return False
        
           
    def get_teams_of_sc_ag_with_id(request,sc_ag_primary):
        '''Returns the Active teams of all Branch+Sc AG'''
        try:

            teams=Teams.objects.filter(is_active=True,team_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary)).all().order_by('id')
            return teams
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"An internal Database error occured loading the Positions for Executive Members!")
            return False
    
    def get_team_details(request,team_primary):
        '''Returns the object of team'''
        
        try:
            team_details=Teams.objects.get(primary=team_primary)
            return team_details
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"An internal Database error occured loading the Team Details!")
            return False
    
    def get_current_panel():
        '''Returns the id of the current panel of IEEE NSU SB'''
        try:            
            current_panel=Panels.objects.get(current=True,panel_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=1))
            return current_panel.pk
        except Panels.DoesNotExist:
            return False
        except sqlite3.OperationalError:
            return False
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            return False
    
    def get_specific_team_members_of_current_panel(request,team_primary):
        try:
            current_panel=PortData.get_current_panel()
            if(current_panel):
                get_current_panel_members=Panel_Members.objects.filter(
                    tenure=Panels.objects.get(pk=current_panel),
                    team=Teams.objects.get(primary=team_primary)
                )
                return get_current_panel_members
            else:
                messages.info("There is no current panel available to load the teams!")
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            return False

    def create_positions(request,sc_ag_primary,role,is_eb_member,is_sc_ag_eb_member,is_officer,is_co_ordinator,is_faculty,is_mentor,
                        is_core_volunteer,is_volunteer):
        '''Creates Positions in the Roles and Positions Table with Different attributes for sc ag and branch as well'''
        try:
            # get the last object of the model
            get_the_last_object=Roles_and_Position.objects.all().order_by('id').last()
            print(get_the_last_object.pk)
            # The logic of creating new position is to assign the id = las objects id + 1.
            # this ensures that ids never conflict with each other
            check_if_same_position_exists=Roles_and_Position.objects.filter(role=role,role_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary),
                                                                            is_eb_member=is_eb_member,is_sc_ag_eb_member=is_sc_ag_eb_member,
                                                                            is_officer=is_officer,is_co_ordinator=is_co_ordinator,is_faculty=is_faculty,is_mentor=is_mentor,
                                                                            is_core_volunteer = is_core_volunteer,is_volunteer = is_volunteer
                                                                            )
            if(check_if_same_position_exists.exists()):
                messages.warning(request,f"A same position {check_if_same_position_exists.first().role} already exists in the Database. Creating same position with same attributes will cause conflicts!")
                return False
            else:            
                new_position=Roles_and_Position.objects.create(
                    id=get_the_last_object.id + 1,
                    role=role,role_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary),
                    is_eb_member=is_eb_member,is_sc_ag_eb_member=is_sc_ag_eb_member,
                    is_officer=is_officer,is_co_ordinator=is_co_ordinator,is_faculty=is_faculty,is_mentor=is_mentor,
                    is_core_volunteer = is_core_volunteer,is_volunteer = is_volunteer
                )
                new_position.save()
                messages.success(request,f"New Position: {role} was created!")
                return True
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            return False
    
    def create_team(request,sc_ag_primary,team_name):
        '''Creates a Team with given name for sc ag and branch'''
        try:    
            get_the_last_team_primary=Teams.objects.all().order_by('-primary').first()
            # The logic of creating new Team is to assign the primary = last objects primary + 1.
            # this ensures that primary of teams never conflict with each other
            new_team=Teams.objects.create(
                team_name=team_name,
                primary=get_the_last_team_primary.primary + 1,
                team_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary)
            )
            messages.success(request,f"A new team : {new_team.team_name} was created!")
            new_team.save()
            return True
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"Error Creating Team. Something went wrong!")
            return False
        
    def get_sc_ag_current_panel(request,sc_ag_primary):
        # returns the object of current panels of sc ag
        current_panel=Panels.objects.filter(panel_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary),current=True).first()
        return current_panel
    
    def get_branch_previous_position_data(ieee_id):
        '''Returns all previous position data for a member'''
        
        previous_position = Panel_Members.objects.filter(member=Members.objects.get(ieee_id=ieee_id),tenure__panel_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=1),tenure__current=False).order_by('-tenure__year')
        return previous_position
    
    def get_sc_ag_previous_position_data(request,ieee_id):
        '''Returns a dictionary of all previous position data for a sc_ag member for all sc_ag'''

        #list for storing all previous sc_ag position data into a dict
        sc_ag_previous_positions = {}
        #get all sc_ag info
        all_sc_ag = PortData.get_all_sc_ag(request)
        #loop each sc_ag and check if there is a previous position
        for sc_ag in all_sc_ag:
            #get position data for each sc_ag
            position_data = Panel_Members.objects.filter(member=Members.objects.get(ieee_id=ieee_id),tenure__panel_of=sc_ag,tenure__current=False).order_by('-tenure__year')
            #if a position exists then add it in the dict
            if position_data.count() > 0:
                sc_ag_previous_positions.update({sc_ag.primary:position_data})
                
        return sc_ag_previous_positions
    
    def get_all_panels(request,sc_ag_primary):
        '''returns the objects of all panels for specific sc ag + branch as a queryset'''
        try:
            get_all_panels=Panels.objects.filter(panel_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary)).order_by('-current','-year')
            return get_all_panels
        except Exception as e:
            PortData.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            messages.error(request,"Error loading Panels. Something went wrong!")
            return False
                      