from datetime import datetime, time
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
import os
from users import renderData
from insb_port import settings
from meeting_minutes.models import MeetingMinutes
from django.views.decorators.csrf import csrf_exempt
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

from port.renderData import PortData
# from . import renderData
# from meeting_minutes.renderData import team_mm_info,branch_mm_info

# Create your views here.

# def team_meeting_minutes(request):
#     '''
#     Loads all the teams' exisitng meeting minutes
#     Gives option to add or delete a meeting minutes
#     '''
     
#     #load teams' meeting minutes from database
    
#     teams_mm=renderData.team_meeting_minutes.load_all_team_mm()
#     team_mm_list=[]
#     for team in teams_mm:
#         team_mm_list.append(team)
#     context={
#         'team':team_mm_list
#     }

#     return render(request,'team_meeting_minutes.html')


# def branch_meeting_minutes(request):
#     '''
#     Loads all the branchs' existing meeting minutes
#     Gives option to add or delete a meeting minutes
#     '''
    
#     #load branchs' meeting minutes from database
    
#     branch_mm=renderData.branch_meeting_minutes.load_all_branch_mm()
#     branch_mm_list=[]
#     for branch in branch_mm:
#         branch_mm_list.append(branch)
#     context={
#         'team':branch_mm_list
#     }
#     return render(request,'branch_meeting_minutes.html')


#     #meeting_minutes_edit


def meeting_minutes_homepage(request, primary=None):
    sc_ag=PortData.get_all_sc_ag(request=request)
    current_user=renderData.LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
    user_data=current_user.getUserData() #getting user data as dictionary file
    get_sc_ag_info=None
        
    meetings = MeetingMinutes.objects.all().order_by('-meeting_date')
    
    context = {
        'all_sc_ag':sc_ag,
        'sc_ag_info':get_sc_ag_info,
        'user_data':user_data,
        'primary': primary,
        'meetings': meetings,
    }
    return render(request, 'meeting_minutes_homepage.html', context)

def meeting_minutes_create(request, primary=None):
    if request.method == 'POST':
        location = request.POST.get('location')
        start_time = request.POST.get('start_time')
        end_time = request.POST.get('end_time')
        meeting_date=request.POST.get('meeting_date')
        
        venue = request.POST.get('venue')
        total_attendee = int(request.POST.get('total_attendees', 0))
        ieee_attendee = request.POST.get('ieee_attendee')
        non_ieee_attendee = request.POST.get('non_ieee_attendee')
        agendas = request.POST.getlist('agenda[]')
        discussion = request.POST.get('discussion')
        host = request.POST.get('host')
        co_host = request.POST.get('co_host')
        guest = request.POST.get('guest')
        written_by = request.POST.get('written_by')
        meeting_name = request.POST.get('meeting_name')

        MeetingMinutes.objects.create(
            meeting_name=meeting_name,
            location=location,
            start_time=start_time,
            end_time=end_time,
            meeting_date=meeting_date,
            venue=venue,
            total_attendee=total_attendee,
            ieee_attendee=ieee_attendee,
            non_ieee_attendee=non_ieee_attendee,
            agendas=agendas,
            discussion=discussion,
            host=host,
            co_host=co_host,
            guest=guest,
            written_by=written_by
        )

        return redirect('central_branch:meeting_minutes:meeting_minutes_homepage')

    return render(request, 'meeting_minutes_edit.html', {'meeting': None})


def meeting_minutes_edit(request, pk):
    meeting = MeetingMinutes.objects.get(pk=pk)

    if request.method == 'POST':
        if 'save' in request.POST:
            location = request.POST.get('location')
            start_time = request.POST.get('start_time')
            end_time = request.POST.get('end_time')

            
            meeting.meeting_date=request.POST.get('meeting_date')
            meeting.meeting_name = request.POST.get('meeting_name')
            meeting.location = location
            meeting.start_time = start_time
            meeting.end_time = end_time
            meeting.venue = request.POST.get('venue')
            meeting.total_attendee = int(request.POST.get('total_attendees', 0))
            meeting.ieee_attendee = request.POST.get('ieee_attendee')
            meeting.non_ieee_attendee = request.POST.get('non_ieee_attendee')
            meeting.agendas = request.POST.getlist('agenda[]')
            meeting.discussion = request.POST.get('discussion')
            meeting.host = request.POST.get('host')
            meeting.co_host = request.POST.get('co_host')
            meeting.guest = request.POST.get('guest')
            meeting.written_by = request.POST.get('written_by')

            meeting.save()
            
        elif 'delete' in request.POST:
            meeting.delete()

        return redirect('central_branch:meeting_minutes:meeting_minutes_homepage')

    return render(request, 'meeting_minutes_edit.html', {'meeting': meeting})


def download_meeting_pdf(request, pk):
    # Try to fetch the meeting by primary key
    try:
        meeting = MeetingMinutes.objects.get(pk=pk)
    except MeetingMinutes.DoesNotExist:
        return HttpResponse("Meeting not found.", status=404)

    # Set up HTTP response headers for PDF download
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'inline; filename="meeting_{pk}.pdf"'

    # Create a canvas object for drawing the PDF
    p = canvas.Canvas(response, pagesize=A4)
    width, height = A4  # Page size

    # Start position from the top of the page
    y = height - 100
    line_height = 30  # Space between lines
    
    logo_path = os.path.join(settings.BASE_DIR, 'meeting_minutes', 'static', 'images', 'logo.jpg')  
    if os.path.exists(logo_path):
        p.drawImage(
    ImageReader(logo_path),
    x=500, y=height - 100,  # Position
    width=80, height=80,   # Size
    preserveAspectRatio=True,
    mask='auto'            
)
        
    print("LOGO PATH:", logo_path)
    print("Exists:", os.path.exists(logo_path))    

   
    p.saveState()
    p.setFont("Helvetica", 40)
    p.setFillColorRGB(0.7, 0.9, 1.0, alpha=0.5)
    p.drawCentredString(width / 2, height / 2, "IEEE NSU Student Branch")
    p.restoreState()

    # Helper function to draw each field in the PDF
    def draw_line(label, value):
        nonlocal y
        p.setFont("Helvetica", 16)
        p.drawString(50, y, f"{label}: {value}")
        y -= line_height

   # Write meeting fields to PDF
    draw_line("Meeting Name", meeting.meeting_name)
    draw_line("Date", meeting.meeting_date.strftime("%Y-%m-%d"))
    draw_line("Time", f"{meeting.start_time.strftime('%H:%M')} - {meeting.end_time.strftime('%H:%M')}")
    draw_line("Location", meeting.location)
    draw_line("Venue", meeting.venue or "N/A")
    draw_line("Total Attendees", str(meeting.total_attendee))
    draw_line("IEEE Attendees", str(meeting.ieee_attendee) if meeting.ieee_attendee is not None else "N/A")
    draw_line("Non-IEEE Attendees", str(meeting.non_ieee_attendee) if meeting.non_ieee_attendee is not None else "N/A")
    draw_line("Agendas", meeting.agendas)
    
    draw_line("Host", meeting.host or "N/A")
    draw_line("Co-host", meeting.co_host or "N/A")
    draw_line("Guest", meeting.guest or "N/A")
    draw_line("Written by", meeting.written_by)
    # Add the "Discussion" section
    p.drawString(50, y, "Discussion:")
    y -= line_height

    # Begin text block for discussion content (multi-line)
    text_object = p.beginText(50, y)
    text_object.setFont("Helvetica", 12)

    # Write each line of discussion to the PDF
    for line in meeting.discussion.splitlines():
        text_object.textLine(line)

    p.drawText(text_object)

    # Finalize and close the PDF document
    p.showPage()
    p.save()

    # Return the response as a downloadable PDF
    return response