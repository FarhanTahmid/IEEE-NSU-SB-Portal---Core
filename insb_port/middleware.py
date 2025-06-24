from typing import Any
from system_administration.models import system
from system_administration.render_access import Access_Render
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from main_website.urls import urlpatterns

class BlockSiteMiddleWare:
    '''This class is basically designed to make the main website go down and show message of its updating'''
    def __init__(self,get_response):
        self.get_response=get_response
        
    def __call__(self,request):
        if(Access_Render.system_administrator_superuser_access(username=request.user.username) or Access_Render.system_administrator_staffuser_access(username=request.user.username)
           or Access_Render.eb_access(username=request.user.username) or Access_Render.belongs_to_sc_ag_panels(username=request.user.username)):
            return self.get_response(request)
        else:
            
            try:
                # first get from the system model
                get_system=system.objects.first()

                # if the 'system_under_maintenance' is true
                path = request.path.split('/')
                if get_system.system_under_maintenance:
                    if (path[1] != 'admin' and not path[1] == 'media_files' and not path[1] == 'static'):
                        return render(request,'main_web_update_view.html')
                    
                if get_system.portal_under_maintenance:
                    allowed_urls = [
                        '/portal',
                        '/portal/users/login',
                        '/portal/users/logout',
                        '/portal/system_administration'
                    ]
                    
                    if not any(request.path == url or request.path == (url + '/') for url in allowed_urls):
                        if (path[1] != 'admin'):
                            if path[1] == 'portal':
                                return render(request, 'main_portal_update_view.html')
                            
                if get_system.main_website_under_maintenance:
                    for i in urlpatterns:
                        # get the url patterns of main website
                        pattern=str(i.pattern)
                        # check if the current url matches with main website. if matches block all the URLs and show the Updating page.
                        if (request.path[1:]==pattern):
                            return redirect('system_administration:main_web_update')
                            
            except:
                print("All okay")
            response=self.get_response(request)
            return response