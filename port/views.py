import os
from django.http import HttpResponseBadRequest
from django.shortcuts import render,redirect
from central_branch.view_access import Branch_View_Access
from central_events.google_calendar_handler import CalendarHandler
from system_administration.google_authorisation_handler import GoogleAuthorisationHandler
from system_administration.models import Project_leads,Project_Developers
from django.conf import settings
import traceback
import logging
from system_administration.render_access import Access_Render
from system_administration.system_error_handling import ErrorHandling
from datetime import datetime
from central_branch import views as cv
from django.contrib import messages
from central_events.google_calendar_handler import GoogleAuthorisationHandler

logger=logging.getLogger(__name__)


# Create your views here.
def homepage(request):

    try:
        #check if user is already logged in
        user=request.user
        if (user.is_authenticated):
            return redirect('users:dashboard')
        else:
            return render(request,'port/landing_page.html')
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

def developed_by(request):
    '''This function loads and shows all the developers for the site'''

    try:

        #load leads and the developers of the project
        project_leads=Project_leads.objects.all()
        project_developers=Project_Developers.objects.all().order_by('-reputation_point')
        
        context={
            'project_leads':project_leads,
            'project_developers':project_developers,
            'media':settings.MEDIA_URL
        }
        return render(request,'port/developer_intro.html',context)
    
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
        
        
def authorize(request):

    if(Access_Render.system_administrator_staffuser_access(request) or Access_Render.system_administrator_superuser_access):
        credentials = GoogleAuthorisationHandler.get_credentials(request)
        if not credentials:
            flow = CalendarHandler.get_google_auth_flow(request)
            if(request.META['HTTP_HOST'] == "127.0.0.1:8000" or request.META['HTTP_HOST'] == "localhost:8000"):
                authorization_url, state = flow.authorization_url(
                    access_type='offline',
                    include_granted_scopes='true',
                )
            else:
                authorization_url, state = flow.authorization_url(
                    access_type='offline',
                    include_granted_scopes='true',
                    login_hint='ieeensusb.portal@gmail.com'
                )
            request.session['state'] = state
            return redirect(authorization_url)

        if credentials != None:
            messages.success(request, "Already authorized!")    
        return redirect('central_branch:event_control')
    else:
        messages.info(request, "You do not have access to this!")
        return redirect('central_branch:event_control')

def oauth2callback(request):
    try:
        if(request.META['HTTP_HOST'] == "127.0.0.1:8000" or request.META['HTTP_HOST'] == "localhost:8000"):
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        state = request.GET.get('state')
        if state != request.session.pop('state', None):
            return HttpResponseBadRequest('Invalid state parameter')
        
        flow = CalendarHandler.get_google_auth_flow(request)
        flow.fetch_token(authorization_response=request.build_absolute_uri())
        credentials = flow.credentials
        GoogleAuthorisationHandler.save_credentials(credentials)
        messages.success(request, "Authorized")
        return redirect('central_branch:event_control')
    except:
        messages.warning(request, "Access Denied!")
        return redirect('central_branch:event_control')