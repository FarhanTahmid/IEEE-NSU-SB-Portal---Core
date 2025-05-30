
from django.urls import path,include
from recruitment import views
from . views import DepartmentAjax,MajorAjax

app_name='recruitment'

##defining the urls to work with

urlpatterns = [
    #path('members/',views.MemberList.as_view()),
    path('',views.recruitment_home,name='recruitment_home'),
    path('recruited_member_list/<str:pk>',views.recruitee,name="recruitee"), #here pk is the id of the session we are accessing
    path('recruited_member/<int:session_id>/<int:nsu_id>',views.recruitee_details,name="recruitee_details"),
    path('membership_form/<int:session_id>',views.recruit_member,name="recruit_member"),
    path('export_excel/<int:session_id>',views.generateExcelSheet,name="export_excel"),
    path('getPaymentStats/',views.getPaymentStats,name="payment_stats"),
    path('get_departments/',DepartmentAjax.as_view(),name="get_departments"),
    path('get_majors/',MajorAjax.as_view(),name='get_majors'),

]