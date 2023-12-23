from .models import HomePageTopBanner,BannerPictureWithStat
from django.http import HttpResponseServerError
from users.models import Members
from membership_development_team.renderData import MDT_DATA
from central_events.models import Events
from port.models import Chapters_Society_and_Affinity_Groups
from graphics_team.models import Graphics_Banner_Image
from media_team.models import Media_Images
class HomepageItems:

    def load_all_events(flag):
        dic = {}
        if flag:
            events =  Events.objects.filter(publish_in_main_web= True).order_by('-event_date')
        else:
            events = Events.objects.filter(publish_in_main_web= True).order_by('-event_date')[:5]
        for i in events:
            try:
                event = Graphics_Banner_Image.objects.get(event_id = i.pk)
                dic.update({i:event.selected_image})
            except:
                dic.update({i:"#"})
        return dic
    
    def load_event_banner_image(event_id):
        try:
            return Graphics_Banner_Image.objects.get(event_id = event_id).selected_image
        except:
            return False
    
    def load_event_gallery_images(event_id):
        return Media_Images.objects.filter(event_id = event_id)

        



    def getHomepageBannerItems():
        try:
            return HomePageTopBanner.objects.all()
            pass
        except Exception as e:
            print(e)
            response = HttpResponseServerError("Oops! Something went wrong.")
            return response
    def getBannerPictureWithStat():
        try:
            getItem=BannerPictureWithStat.objects.first()
            return getItem.image
        except Exception as e:
            print(e)
            response = HttpResponseServerError("Oops! Something went wrong.")
            return response
        
    def getAllIEEEMemberCount():
        '''Gets all the count of members in Database'''
        return Members.objects.all().count()
    
    def getActiveMemberCount():
        '''Gets all the active Member count'''
        activeMemberCount=0
        
        allMembers=Members.objects.all()

        for i in allMembers:
            if(MDT_DATA.get_member_account_status(i.ieee_id)):
                activeMemberCount+=1

        return activeMemberCount
    
    def getEventCount():
        '''Gets all the event Count'''
        return Events.objects.all().count()
    
        
