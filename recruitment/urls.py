import imp
from django.urls import path,include
from recruitment import views

app_name='recruitment'

##defining the urls to work with

urlpatterns = [
    #path('members/',views.MemberList.as_view()),
    path('',views.recruitment_home,name='recruitment_home'),
    path('recruitee',views.recruitee,name="recruitee"),
    path('form',views.recruit_member,name="recruit member")
    
]