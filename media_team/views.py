from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from system_administration.render_access import Access_Render
from users.models import Members
from central_branch.renderData import Branch
from port.models import Roles_and_Position
from django.contrib import messages
from system_administration.models import Media_Data_Access
from .renderData import MediaTeam
from central_branch.models import Events,InterBranchCollaborations
from django.db.models import Q
from .models import Media_Link,Media_Images
from django.conf import settings
from . import renderData
from users.renderData import LoggedinUser


# Create your views here.
@login_required
def team_homepage(request):

    #Loading data of the co-ordinators, co ordinator id is 9,
    co_ordinators=renderData.MediaTeam.get_member_with_postion(9)
    #Loading data of the incharges, incharge id is 10
    in_charges=renderData.MediaTeam.get_member_with_postion(10)
    current_user=LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
    user_data=current_user.getUserData() #getting user data as dictionary file
    context={
        'co_ordinators':co_ordinators,
        'incharges':in_charges,
        'media_url':settings.MEDIA_URL,
        'user_data':user_data,
    }

    
    return render(request,"HomePage/media_homepage.html")

@login_required
def manage_team(request):

    '''This function loads the manage team page for media team and is accessable
    by the co-ordinatior only, unless the co-ordinators gives access to others as well'''
    user = request.user
    has_access=(Access_Render.team_co_ordinator_access(team_id=MediaTeam.get_team_id(),username=user.username) or Access_Render.system_administrator_superuser_access(user.username) or Access_Render.system_administrator_staffuser_access(user.username) or Access_Render.eb_access(user.username)
    or MediaTeam.media_manage_team_access(user.username))

    data_access = MediaTeam.load_manage_team_access()
    team_members = MediaTeam.load_team_members()
    #load all position for insb members
    position=Branch.load_roles_and_positions()
    #load all insb members
    all_insb_members=Members.objects.all()

    if request.method == "POST":
        if (request.POST.get('add_member_to_team')):
            #get selected members
            members_to_add=request.POST.getlist('member_select1')
            #get position
            position=request.POST.get('position')
            print(position)
            print(members_to_add)
            for member in members_to_add:
                MediaTeam.add_member_to_team(member,position)
            return redirect('media_team:manage_team')
        
        if (request.POST.get('remove_member')):
            '''To remove member from team table'''
            x = request.POST.get('remove_ieee_id')
            print(x)
            try:
                Members.objects.filter(ieee_id=request.POST['remove_ieee_id']).update(team=None,position=Roles_and_Position.objects.get(id=13))
                try:
                    Media_Data_Access.objects.filter(ieee_id=request.POST['remove_ieee_id']).delete()
                except Media_Data_Access.DoesNotExist:
                     return redirect('media_team:manage_team')
                return redirect('media_team:manage_team')
            except:
                pass

        if request.POST.get('access_update'):
            manage_team_access = False
            if(request.POST.get('manage_team_access')):
                manage_team_access=True
            ieee_id=request.POST['access_ieee_id']
            if (MediaTeam.media_manage_team_access_modifications(manage_team_access,ieee_id)):
                permission_updated_for=Members.objects.get(ieee_id=ieee_id)
                messages.info(request,f"Permission Details Was Updated for {permission_updated_for.name}")
            else:
                messages.info(request,f"Something Went Wrong! Please Contact System Administrator about this issue")

        if request.POST.get('access_remove'):
            '''To remove record from data access table'''
            
            ieeeId=request.POST['access_ieee_id']
            if(MediaTeam.remove_member_from_manage_team_access(ieee_id=ieeeId)):
                messages.info(request,"Removed member from Managing Team")
                return redirect('media_team:manage_team')
            else:
                messages.info(request,"Something went wrong!")

        if request.POST.get('update_data_access_member'):
            
            new_data_access_member_list=request.POST.getlist('member_select')
            
            if(len(new_data_access_member_list)>0):
                for ieeeID in new_data_access_member_list:
                    if(MediaTeam.add_member_to_manage_team_access(ieeeID)=="exists"):
                        messages.info(request,f"The member with IEEE Id: {ieeeID} already exists in the Data Access Table")
                    elif(MediaTeam.add_member_to_manage_team_access(ieeeID)==False):
                        messages.info(request,"Something Went wrong! Please try again")
                    elif(MediaTeam.add_member_to_manage_team_access(ieeeID)==True):
                        messages.info(request,f"Member with {ieeeID} was added to the team table!")
                        return redirect('media_team:manage_team')


    context={
        'data_access':data_access,
        'members':team_members,
        'insb_members':all_insb_members,
        'positions':position,
        
    }

    if has_access:
        return render(request,"media_team/manage_team.html",context=context)
    return render(request,"media_team/access_denied.html")

@login_required
def event_page(request):

    '''Only events organised by INSB would be shown on the event page of Media Team
       So, only those events are being retrieved from database'''
    insb_organised_events = Events.objects.filter(event_organiser=5).order_by('-event_date')
    print(insb_organised_events)
    #media_link = Media_Link.objects.get(event_id=Events.objects.get(id = event_id))
    #media_img = Media_Images.objects.get(event_id=Events.objects.get(id = event_id))
    #drive_link = media_link.media_link
    #logo_link = media_link.logo_link
    #Img = media_img.selected_images
    


    





    context = {'events_of_insb_only':insb_organised_events,
                }


    return render(request,"Events/media_event_homepage.html",context)

@login_required
def event_form(request,event_ID):
    event_id = event_ID
    event = Events.objects.get(id = event_id)
    print(event)
    media = Media_Link.objects.filter(event_id = event)
    Img  = Media_Images.objects.filter(event_id = event)
    try:
        media_link = media[0].media_link
        logo_link = media[0].logo_link
        Img_photo = Img
        exist=True
    except:
        exist=False
        media_link=None
        logo_link=None
        Img_photo=None


    if request.method=="POST":
        if request.POST.get('add_event_pic_and_others'):
            targetted_event = Events.objects.get(id = event_id)
            drive_link_of_event = request.POST.get('drive_link_of_event')
            print(drive_link_of_event)
            logo_link_of_event = request.POST.get('logo_link_of_event')
            images= request.FILES.getlist('images')
            print(images)
            if len(images)==0:
                if exist:
                    media_id = media[0].id
                    extracted_from_table = Media_Link.objects.get(id = media_id)
                    extracted_from_table.media_link = drive_link_of_event
                    extracted_from_table.logo_link = logo_link_of_event
                    extracted_from_table.save()
                    return redirect('media_team:event_page')
                else:
                    try:
                        links = Media_Link.objects.create(
                        event_id = targetted_event,
                        media_link = drive_link_of_event,
                        logo_link = logo_link_of_event
                        )
                        links.save()
                        messages.success(request,"Successfully Added!")
                        return redirect('media_team:event_page')
                    except:
                        print("Error")
                    
                
                
            else:
                try:
                    links = Media_Link.objects.create(
                    event_id = targetted_event,
                    media_link = drive_link_of_event,
                    logo_link = logo_link_of_event
                    )
                    links.save()
                    for image in images:
                        Image_save = Media_Images.objects.create(
                        event_id = targetted_event,
                        selected_images = image
                        )
                        Image_save.save()
                    messages.success(request,"Successfully Added!")
                    return redirect('media_team:event_page')
                except:
                    print("Error")
                
            
            

        if request.POST.get('submitted_changed_picture'):
            try:
                picture_id= request.POST.get('ImageID')
                print(picture_id)
                picture = Media_Images.objects.get(id=picture_id)
                new_picture = request.FILES['new_image']
                print(new_picture)
                picture.selected_images = new_picture
                picture.save()
                return redirect('media_team:event_page')
            except:
                print("Error")
           





    context={
        'media_link':media_link,
        'logo_link':logo_link,
        'Img':Img_photo,
        'exist':exist,
        'media_url':settings.MEDIA_URL,
        'event_name':event.event_name,
    }

    return render(request,"media_team/media_event_form.html",context)


