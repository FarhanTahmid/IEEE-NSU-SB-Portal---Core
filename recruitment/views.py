from django.shortcuts import render,redirect
from django.db import DatabaseError,IntegrityError,InternalError
from django.http import HttpResponseServerError,HttpResponseBadRequest,HttpResponse
from recruitment.models import recruitment_session,recruited_members
from users.models import Members
from . import renderData
from django.contrib.auth.decorators import login_required
from . forms import StudentForm
from . models import recruited_members
from django.contrib import messages
import datetime
from django.core.exceptions import ObjectDoesNotExist
import xlwt

# Create your views here.

@login_required
def recruitment_home(request):
    
    '''Loads all the recruitment sessions present in the database
        this can also register a recruitment session upon data entry
        this passes all the datas into the template file    
    '''
    
    numberOfSessions=renderData.Recruitment.loadSession()
    if request.method=="POST":
        session_name=request.POST["recruitment_session"]
        try:
            add_session=recruitment_session(session=session_name)
            add_session.save()
        except DatabaseError:
            return DatabaseError
    return render(request,'recruitment_home.html',numberOfSessions)


@login_required  
def recruitee(request,pk):
    
    '''This function is responsible for getting all the members registered in a particular
    recruitment session. Loads all the datas and show them
    '''
    getSession=renderData.Recruitment.getSession(session_id=pk)
    getMemberCount=renderData.Recruitment.getTotalNumberOfMembers(int(pk))
    getRecruitedMembers=renderData.Recruitment.getRecruitedMembers(session_id=pk)

    context={
        'memberCount':getMemberCount,
        'session':getSession,
        'members':getRecruitedMembers,
       }
    return render(request,'recruitees.html',context=context)


@login_required
def recruitee_details(request,nsu_id):
    """Preloads all the data of the recruitees who are registered in the particular session, here we can edit and save the data of the recruitee"""
    try:
        
        data=renderData.Recruitment.getRecruitedMemberDetails(nsu_id=nsu_id)
        #this parses the date in -DD-MM-YY Format for html
        dob=datetime.datetime.strptime(str(data['recruited_member'][0]['date_of_birth']), "%Y-%m-%d").strftime("%Y-%m-%d") #this dob does not change any internal data, it is used just to convert the string type from database to load in to html
    
    except ObjectDoesNotExist:
        #if object doesnot exist...
        messages.info(request,"Member does not exist!")
    except:
        #goes to recruitment home if list_index_out_of bound occures
        return redirect('recruitment:recruitment_home')
    
    #Passing data to the template
    context={
             'session':str((data['recruited_member'][0]['session_id'])),
             'data':data,
             'dob':dob
             }
    
    if request.method=="POST":
        
        #####this is used to update the recruited member details
        #Upon entering IEEE id this registers members to the main database of members
        if request.POST.get('save_edit'): 
            
            # checks the marked check-boxes
            cash_payment_status=False
            if request.POST.get('cash_payment_status'):
                cash_payment_status=True
            ieee_payment_status=False
            if request.POST.get('ieee_payment_status'):
                ieee_payment_status=True
            #Collecting all infos
            info_dict={
                'first_name':request.POST['first_name'],
                'middle_name':request.POST['middle_name'],
                'last_name':request.POST['last_name'],
                'contact_no':request.POST['contact_no'],
                'date_of_birth':request.POST['date_of_birth'],
                'email_personal':request.POST['email_personal'],
                'facebook_url':request.POST['facebook_url'],
                'home_address':request.POST['home_address'],
                'major':request.POST['major'], 'graduating_year':request.POST['graduating_year'],
                'ieee_id':request.POST['ieee_id'],
                'recruited_by':request.POST['recruited_by'],
                'cash_payment_status':cash_payment_status,
                'ieee_payment_status':ieee_payment_status
            }
            
            #Getting returned values and handling the exceptions
            
            if(renderData.Recruitment.updateRecruiteeDetails(nsu_id=nsu_id,values=info_dict)=="no_ieee_id"):
                messages.info(request,"Please Enter IEEE ID if you have completed payment")
                return redirect('recruitment:recruitee_details',nsu_id)
            elif(renderData.Recruitment.updateRecruiteeDetails(nsu_id=nsu_id,values=info_dict)==IntegrityError):
                messages.info(request,"There is already a member registered with this IEEE ID")
                return redirect('recruitment:recruitee_details',nsu_id)
            elif((renderData.Recruitment.updateRecruiteeDetails(nsu_id=nsu_id,values=info_dict)=="no_ieee_id")==InternalError):
                messages.info(request,"A Server Error Occured!")
                return redirect('recruitment:recruitee_details',nsu_id)
            elif((renderData.Recruitment.updateRecruiteeDetails(nsu_id=nsu_id,values=info_dict)=="no_ieee_id")=="already_registered"):
                messages.info(request,"This member is already registered in INSB Database! If you still want to edit information for this member, redirect to members segment!")
                return redirect('recruitment:recruitee_details',nsu_id)
            elif((renderData.Recruitment.updateRecruiteeDetails(nsu_id=nsu_id,values=info_dict)=="no_ieee_id")=="success"):
                messages.info(request,"Information Updated")
                return redirect('recruitment:recruitee_details',nsu_id)
            else:
                messages.info(request,"This IEEE id is already registered in the main database. Can not Update and Overwrite the info in main Database!")
                return redirect('recruitment:recruitee_details',nsu_id)
        
        
        
        #####DELETING RECRUITEES#######
        if request.POST.get('delete_member'):
            if(renderData.Recruitment.deleteMember(nsu_id=nsu_id)=="both_database"):
                messages.info(request,f"Member Deleted Successfully from recruitment process and also from INSB Database with the id {nsu_id}")
            elif(renderData.Recruitment.deleteMember(nsu_id=nsu_id)==ObjectDoesNotExist):
                messages.info(request,f"The member with the id {nsu_id} was deleted!")
            elif(renderData.Recruitment.deleteMember(nsu_id=nsu_id)):
                messages.info(request,f"The member with the id {nsu_id} was deleted!")
            else:
                messages.info(request,f"Something went wrong! Try again!")
                return redirect('recruitment:recruitee_details',nsu_id)


        #####REGISTERING MEMBER IN INSB DATABASE####

        if request.POST.get("register_member"):
            getMember=recruited_members.objects.filter(nsu_id=nsu_id).values(
                'ieee_id',
                'first_name','middle_name','last_name',
                'nsu_id',
                'email_personal',
                'contact_no',
                'home_address',
                'date_of_birth',
                'gender',
                'facebook_url',
                'session_id',
                'ieee_payment_status'
            )
            
            # Registering member to the main database
            checkMember=Members.objects.filter(nsu_id=nsu_id).values('ieee_id')

            ###PROBLEM HERE SOLVE#####

            if Members.objects.get(nsu_id=nsu_id).exists():
                messages.info(request,"Member already exists in INSB Database")
                return redirect('recruitment:recruitee_details',nsu_id)
            else:
                if getMember[0]['ieee_payment_status'] and getMember[0]['ieee_id'] != '':
                    if (Members.objects.get(ieee_id=int(checkMember[0]['ieee_id'])).exists()):
                        messages.info(request,"Member is already registered in the INSB Database")
                    else:
                        newMember = Members(
                        ieee_id=int(getMember[0]['ieee_id']),
                        name=getMember[0]['first_name'] + " " +
                        getMember[0]['middle_name']+" " +
                        getMember[0]['last_name'],
                        nsu_id=getMember[0]['nsu_id'],
                        email_personal=getMember[0]['email_personal'],
                        contact_no=getMember[0]['contact_no'],
                        home_address=getMember[0]['home_address'],
                            date_of_birth=getMember[0]['date_of_birth'],
                            gender=recruited_members.objects.filter(
                                nsu_id=nsu_id).values('gender'),
                            facebook_url=getMember[0]['facebook_url'],
                            session=recruited_members.objects.filter(
                                nsu_id=nsu_id).values('session_id'),
                        )
                        newMember.save()
                        return redirect('recruitment:recruitee_details',nsu_id)
                else:
                    messages.info(request,"Please enter IEEE ID to register member in the INSB Database")
                    return redirect('recruitment:recruitee_details',nsu_id) 
                    

    return render(request,"recruitee_details.html",context=context)


@login_required
def recruit_member(request,session_name):
    getSessionId=renderData.Recruitment.getSessionid(session_name=session_name)
    form=StudentForm
    context={
        'form':form,
        'session_name':session_name,
        'session_id':getSessionId['session'][0]['id']
    }

    
    #this method is for the POST from the recruitment form
    
    if request.method=="POST":
        
        try:
            
            cash_payment_status=False
            if request.POST.get("cash_payment_status"):
                cash_payment_status=True
            ieee_payment_status=False
            if request.POST.get("ieee_payment_status"):
                ieee_payment_status=True
                
            #getting all data from form and registering user upon validation
            recruited_member=recruited_members(
            nsu_id=request.POST['nsu_id'],
            first_name=request.POST['first_name'],
            middle_name=request.POST['middle_name'],
            last_name=request.POST['last_name'],
            contact_no=request.POST['contact_no'],
            date_of_birth=request.POST['date_of_birth'],
            email_personal=request.POST['email_personal'],
            gender=request.POST['gender'],
            facebook_url=request.POST['facebook_url'],
            home_address=request.POST['home_address'],
            major=request.POST['major'],
            graduating_year=request.POST['graduating_year'],
            session_id=getSessionId['session'][0]['id'],
            recruited_by=request.POST['recruited_by'],
            cash_payment_status=cash_payment_status,
            ieee_payment_status=ieee_payment_status
            )
            recruited_member.save() #Saving the member to the database
            messages.info(request,"Registered Member Successfully!")
            return render(request,"membership_form.html",context=context)
        
        except IntegrityError: #Checking if same id exist and handling the exception
            messages.info(request,f"Member with NSU ID: {request.POST['nsu_id']} is already registered in the database!")
            return render(request,"membership_form.html",context=context)
        
        except: #Handling all errors
            messages.info(request,"Something went Wrong! Please try again")
            return render(request,"membership_form.html",context=context)
    
    else:
        
        return render(request,"membership_form.html",context=context)


def generateExcelSheet(request,session_name):
    '''This method generates the excel files for different sessions'''
    response=HttpResponse(content_type='application/ms-excel') #eclaring content type for the excel files
    response['Content-Disposition']=f'attachment; filename=Recruitment Process of {session_name}---'+\
        str(datetime.datetime.now())+'.xls' #making files downloadable with name
    workBook=xlwt.Workbook(encoding='utf-8') #adding encoding to the workbook
    workSheet=workBook.add_sheet(f'Recruitment-{session_name}')
    
    #generating the first row
    row_num=0
    font_style=xlwt.XFStyle()
    font_style.font.bold=True
    #Defining columns that will stay in the first row
    columns=['NSU ID','First Name','Middle Name','Last Name','Email (personal)','Contact No','IEEE ID','Gender','Date Of Birth',
             'Facebook Url','Address','Major','Graduating Year',
             'Recruitment Time','Recruited By','Cash Payment Status','IEEE Payment Status']
    for column in range(len(columns)):
        workSheet.write(row_num,column,columns[column],font_style)
    font_style=xlwt.XFStyle()
    getSession=renderData.Recruitment.getSessionid(session_name=session_name)
    
    rows=recruited_members.objects.filter(session_id=getSession['session'][0]['id']).values_list('nsu_id',
                                                                        'first_name','middle_name','last_name',
                                                                        'email_personal',
                                                                        'contact_no',
                                                                        'ieee_id',
                                                                        'gender',
                                                                        'date_of_birth',
                                                                        'facebook_url',
                                                                        'home_address',
                                                                        'major','graduating_year',
                                                                        'recruitment_time',
                                                                        'recruited_by',
                                                                        'cash_payment_status',
                                                                        'ieee_payment_status'
                                                                        )
    
    for row in rows:
        
        row_num+=1
        for col_num in range(len(row)):
            workSheet.write(row_num,col_num,str(row[col_num]),font_style)
    workBook.save(response)
    return(response)