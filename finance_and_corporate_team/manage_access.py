
from datetime import datetime
import logging
import traceback
from finance_and_corporate_team.renderData import FinanceAndCorporateTeam
from system_administration.models import FCT_Data_Access
from system_administration.render_access import Access_Render
from system_administration.system_error_handling import ErrorHandling


class FCT_Render_Access:

    logger=logging.getLogger(__name__)

    def get_common_access(request):
        ''' This function checks the common access permissions for users such as administrator or coordinator. It will return True if conditions match. The method takes a REQUEST and verifies access '''
        try:
            # get the user and username. Username will work as IEEE ID and Developer username both
            user=request.user
            username=user.username
            
            # generate superuser or staff user access
            system_manager_access=False
            if(Access_Render.system_administrator_superuser_access(username=username) or Access_Render.system_administrator_staffuser_access(username=username)):
                system_manager_access=True
            
            #generate branch eb access
            branch_eb_access=False
            if(Access_Render.eb_access(username=username)):
                branch_eb_access=True
            
            # generate Faculty Advisor Access
            faculty_advisor_access=False
            if(Access_Render.faculty_advisor_access(username=username)):
                faculty_advisor_access=True

            # generate branch team coordinator access
            branch_team_coordinator_access=False
            if(Access_Render.team_co_ordinator_access(team_id=FinanceAndCorporateTeam.get_team_id(), username=username)):
                branch_team_coordinator_access=True
            
            # if any of this is true, grant access
            if(system_manager_access or branch_eb_access or faculty_advisor_access or branch_team_coordinator_access):
                return True
            else:
                return False
        except Exception as e:
            FCT_Render_Access.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
            ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
            return False
    
    def access_for_manage_team(request):
        ''' This function checks if the requested user has access to manage team. Will return True if it has access permission '''
        try:
            # get the user and username. Username will work as IEEE ID and Developer username both
            user=request.user
            username=user.username

            #Get member from graphics data access table
            get_member = FCT_Data_Access.objects.filter(ieee_id=username)
            #Check if the member exits
            if(get_member.exists()):
                #The member exists. Now check if it has manage team access
                if(get_member[0].manage_team_access or FCT_Render_Access.get_common_access(request)):
                    return True
                else:
                    return False
            else:
                #The member does not exist in the permissions table
                if(FCT_Render_Access.get_common_access(request)):
                    return True
                else:
                    return False
        except Exception as e:
            if(FCT_Render_Access.get_common_access(request)):
                return True
            else:
                FCT_Render_Access.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
                ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
                return False
        
    def access_for_create_budget(request):
        ''' This function checks if the requested user has access to creating a budget. Will return True if it has access permission '''
        try:
            # get the user and username. Username will work as IEEE ID and Developer username both
            user=request.user
            username=user.username

            #Get member from graphics data access table
            get_member = FCT_Data_Access.objects.filter(ieee_id=username)
            #Check if the member exits
            if(get_member.exists()):
                #The member exists. Now check if it has events access
                if(get_member[0].create_budget_access or FCT_Render_Access.get_common_access(request)):
                    return True
                else:
                    return False
            else:
                #The member does not exist in the permissions table
                if(FCT_Render_Access.get_common_access(request)):
                    return True
                else:
                    return False
        except Exception as e:
            if(FCT_Render_Access.get_common_access(request)):
                return True
            else:
                FCT_Render_Access.logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
                ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
                return False