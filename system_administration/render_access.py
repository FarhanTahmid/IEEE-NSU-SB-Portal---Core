from port.models import Chapters_Society_and_Affinity_Groups,Panels
from users.models import Members,Panel_Members
from chapters_and_affinity_group.models import SC_AG_Members
from django.contrib.auth .models import User
from port.renderData import PortData
from django.core.exceptions import ObjectDoesNotExist

class Access_Render:

    '''
    The main theory of access render is to control views for different users
    To control the access of Faculty,EB,officers, the algorithm is
        -check if the member exists in the current running panel set by the system
        -check their positions and cross match if they are EB,co-ordinators or faculty
        -if and only if everything checks up, we return True for access, otherwise its always False.
    '''
    
    def is_panel_member(username):
        '''This fucntion checks if a member belongs to the current panel of INSB'''
        # get panel id, this is only for branch panels
        get_current_panel_id=PortData.get_current_panel()
        # check if member exists
        if(Panel_Members.objects.filter(tenure=get_current_panel_id,member=username).exists()):
            return True
        else:
            return False
        
    def faculty_advisor_access(username):
        try:
            if(Access_Render.is_panel_member(username=username)):
                get_faculty=Members.objects.get(ieee_id=int(username))
                if(get_faculty.position.is_faculty):
                    return True
                else:
                    return False
            else:
                return False
        except Members.DoesNotExist:
            return False
        except:
            return False
        
    def eb_access(username):
        try:
            
            # if member is present in the current panel
            if(Access_Render.is_panel_member(username=username)):
                get_eb=Members.objects.get(ieee_id=int(username))
                if(get_eb.position.is_eb_member):
                    return True
                else:
                    False
            else:
                return False
            
        except Members.DoesNotExist:
            return False
        except:
            return False
    
    def sc_ag_eb_access(username,sc_ag_primary):
        try:
            try:
                get_member_from_sc_ag_database=SC_AG_Members.objects.get(sc_ag=Chapters_Society_and_Affinity_Groups.objects.get(primary=sc_ag_primary),member=Members.objects.get(ieee_id=username))
            except ObjectDoesNotExist:
                return False
            if(get_member_from_sc_ag_database.position.is_sc_ag_eb_member):
                return True
            else:
                return False
        except Exception as e:
            return False
            
    def co_ordinator_access(username):
        
        try:
            # first get if the member exists in the current panel
            if(Access_Render.is_panel_member(username=username)):                # if member is present in the current panel
                get_co_ordinator=Members.objects.get(ieee_id=int(username))
                if(get_co_ordinator.position.is_officer) and (get_co_ordinator.position.is_co_ordinator):
                    return True
                else:
                    return False
            else:
                return False
        except Members.DoesNotExist:
            return False
        except:
            return False
        
    def team_co_ordinator_access(team_id,username):
        try:
            if (Access_Render.is_panel_member(username=username)):
                get_co_ordinator=Members.objects.get(ieee_id=int(username))
                
                if(get_co_ordinator.position.is_officer and (get_co_ordinator.position.is_co_ordinator) and (get_co_ordinator.team.id==team_id)):
                    return True
                else:
                    return False
            else:
                return False
        except Members.DoesNotExist:
            return False
        except:
            return False
    
    def team_officer_access(team_id,username):
        try:
            if (Access_Render.is_panel_member(username=username)):
                get_officer=Members.objects.get(ieee_id=int(username))
                if(get_officer.position.is_officer and (get_officer.team.id==team_id)):
                    return True
                else:
                    return False
            else:
                return False
        except Members.DoesNotExist:
            return False
        except:
            return False
    
    def officer_access(username):
        try:
            if(Access_Render.is_panel_member(username=username)):
                get_officer=Members.objects.get(ieee_id=int(username))
                if(get_officer.position.is_officer):
                    return True
                else:
                    return False
            else:
                return False
        except:
            return False
    
    def team_officer_access(team_id,username):
        try:
            if (Access_Render.is_panel_member(username=username)):
                get_officer=Members.objects.get(ieee_id=int(username))
                
                if(get_officer.position.is_officer and (get_officer.team.id==team_id)):
                    return True
                else:
                    return False
            else:
                return False
        except Members.DoesNotExist:
            return False
        except:
            return False
        
    def system_administrator_superuser_access(username):
        try:
            access=User.objects.get(username=username)
            if(access.is_superuser):
                return True
            else:
                return False
        except:
            return False
    def system_administrator_staffuser_access(username):
        try:
            access=User.objects.get(username=username)
            if(access.is_staff):
                return True
            else:
                return False
        except:
            return False
    
    def belongs_to_sc_ag_panels(username):
        try:
            # get current panels of all sc_ags
            current_panels=Panels.objects.filter(current=True).exclude(panel_of=Chapters_Society_and_Affinity_Groups.objects.get(primary=1))

            member_instances=[]
            
            for i in current_panels:
                member=Panel_Members.objects.filter(member=Members.objects.get(ieee_id=username),tenure=Panels.objects.get(pk=i.pk))
                if member.exists():
                    member_instances.append(member)

            if(len(member_instances)>0):
                for member in member_instances:
                    for i in member:
                        if i.position.is_sc_ag_eb_member:
                            return True
                        else:
                            return False
            else:
                return False
        except:
            return False
    
                
            