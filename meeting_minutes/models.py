from django.db import models
from django.urls import reverse
from port.models import Teams, Chapters_Society_and_Affinity_Groups
# Create your models here.

# meeting minutes' information
# class team_meeting_minutes(models.Model):
#     team_id=models.ForeignKey(Teams,null=False,blank=False,on_delete=models.CASCADE) #team foreign key from each chapters
#     team_meeting_title=models.CharField(null=False,blank=False,max_length=150)
#     team_meeting_date=models.DateField(null=True,blank=True,auto_now_add=False)
#     team_meeting_time=models.TimeField(null=True,blank=True,auto_now_add=False)
#     team_meeting_venue=models.CharField(null=False,blank=False,max_length=150)
#     team_meeting_present=models.CharField(null=False,blank=False,max_length=150)
#     team_meeting_excused=models.CharField(null=False,blank=False,max_length=150)
#     team_meeting_absent=models.CharField(null=False,blank=False,max_length=150)
#     team_meeting_called_by=models.CharField(null=False,blank=False,max_length=150)
#     team_meeting_agendas=models.CharField(null=False,blank=False,max_length=150)
#     team_meeting_approval=models.CharField(null=False,blank=False,max_length=150)
#     team_meeting_discussion=models.CharField(null=False,blank=False,max_length=3000)

#     class Meta:
#         verbose_name="Registered Team Meeting"
    
#     def __str__(self) -> str:
#         return self.meeting_title
#     def get_absolute_url(self):
#         return reverse("team_meetings", kwargs={"meeting_title": self.meeting_title})

# class branch_meeting_minutes(models.Model):
#     branch_or_society_id=models.ForeignKey(Chapters_Society_and_Affinity_Groups, null=False, blank=False, on_delete=models.CASCADE)
#     branch_or_society_meeting_title=models.CharField(null=False,blank=False,max_length=150)
#     branch_or_society_meeting_date=models.DateField(null=True,blank=True,auto_now_add=False)
#     branch_or_society_meeting_time=models.TimeField(null=True,blank=True,auto_now_add=False)
#     branch_or_society_meeting_venue=models.CharField(null=False,blank=False,max_length=150)
#     branch_or_society_meeting_present=models.CharField(null=False,blank=False,max_length=150)
#     branch_or_society_meeting_excused=models.CharField(null=False,blank=False,max_length=150)
#     branch_or_society_meeting_absent=models.CharField(null=False,blank=False,max_length=150)
#     branch_or_society_meeting_called_by=models.CharField(null=False,blank=False,max_length=150)
#     branch_or_society_meeting_agendas=models.CharField(null=False,blank=False,max_length=150)
#     branch_or_society_meeting_approval=models.CharField(null=False,blank=False,max_length=150)
#     branch_or_society_meeting_discussion=models.CharField(null=False,blank=False,max_length=3000)
# #Chapters_Society_and_Affinity_Groups foreign key from each chapters
#     class Meta:
#         verbose_name="Branch - Society Meeting"
    
#     def __str__(self) -> str:
#         return self.meeting_title
#     def get_absolute_url(self):
#         return reverse("branch_meeting_minutes", kwargs={"meeting_title": self.meeting_title})


class MeetingMinutes(models.Model):
    meeting_name = models.CharField(max_length=255)
    location = models.CharField(max_length=50)
    meeting_date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    venue = models.CharField(max_length=255, blank=True, null=True)
    total_attendee = models.IntegerField()
    ieee_attendee = models.IntegerField(blank=True, null=True)
    non_ieee_attendee = models.IntegerField(blank=True, null=True)
    agendas = models.JSONField(default=list)  # ✅ recommended
    discussion = models.TextField()
    host = models.CharField(max_length=255, blank=True, null=True)
    co_host = models.CharField(max_length=255, blank=True, null=True)
    guest = models.CharField(max_length=255, blank=True, null=True)
    written_by = models.CharField(max_length=255)

    def __str__(self):
        return str(self.pk)