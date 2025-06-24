import json
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from django.views import View
import requests
from central_branch.view_access import Branch_View_Access
from central_events.models import Events
from finance_and_corporate_team.manage_access import FCT_Render_Access
from finance_and_corporate_team.models import BudgetSheet, BudgetSheetAccess
from system_administration.render_access import Access_Render
from users.models import Members
from central_branch.renderData import Branch
from port.models import Chapters_Society_and_Affinity_Groups, Roles_and_Position
from django.contrib import messages
from .renderData import FinanceAndCorporateTeam
from system_administration.models import FCT_Data_Access
from port.renderData import PortData
from users import renderData
from users.renderData import PanelMembersData,member_login_permission
import traceback
from datetime import datetime
import logging
from system_administration.system_error_handling import ErrorHandling
from central_branch import views as cv
from .genPDF import BudgetPDF

logger=logging.getLogger(__name__)
# Create your views here.
@login_required
@member_login_permission
def team_homepage(request):

    try:

        sc_ag=PortData.get_all_sc_ag(request=request)
        current_user=renderData.LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        
        # get team members
        get_members=FinanceAndCorporateTeam.load_team_members_with_positions()
        
        context={
                'user_data':user_data,
                'all_sc_ag':sc_ag,
                'co_ordinators':get_members[0],
                'incharges':get_members[1],
                'core_volunteers':get_members[2],
                'team_volunteers':get_members[3],
            }
        return render(request,"finance_and_corporate_team/team_homepage.html",context=context)
    
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def manage_team(request):

    try:

        sc_ag=PortData.get_all_sc_ag(request=request)
        current_user=renderData.LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file

        has_access = FCT_Render_Access.access_for_manage_team(request)

        if has_access:
            data_access = FinanceAndCorporateTeam.load_manage_team_access()
            team_members = FinanceAndCorporateTeam.load_team_members()
            #load all position for insb members
            position=PortData.get_all_volunteer_position_with_sc_ag_id(request=request,sc_ag_primary=1)
            #load all insb members
            all_insb_members=Members.objects.all()

            if request.method == "POST":
                if (request.POST.get('add_member_to_team')):
                    #get selected members
                    members_to_add=request.POST.getlist('member_select1')
                    #get position
                    position=request.POST.get('position')
                    for member in members_to_add:
                        FinanceAndCorporateTeam.add_member_to_team(member,position)
                    messages.success(request,"Added new Member to Team!")
                    return redirect('finance_and_corporate_team:manage_team')
                
                if (request.POST.get('remove_member')):
                    '''To remove member from team table'''
                    try:
                        load_current_panel=Branch.load_current_panel()
                        PanelMembersData.remove_member_from_panel(ieee_id=request.POST['remove_ieee_id'],panel_id=load_current_panel.pk,request=request)
                        try:
                            FCT_Data_Access.objects.filter(ieee_id=request.POST['remove_ieee_id']).delete()
                        except FCT_Data_Access.DoesNotExist:
                            return redirect('finance_and_corporate_team:manage_team')
                        return redirect('finance_and_corporate_team:manage_team')
                    except:
                        pass

                if request.POST.get('access_update'):
                    manage_team_access = False
                    if(request.POST.get('manage_team_access')):
                        manage_team_access=True
                    create_budget_access = False
                    if(request.POST.get('create_budget_access')):
                        create_budget_access=True
                    ieee_id=request.POST['access_ieee_id']
                    if (FinanceAndCorporateTeam.fct_manage_team_access_modifications(manage_team_access, create_budget_access, ieee_id)):
                        permission_updated_for=Members.objects.get(ieee_id=ieee_id)
                        messages.info(request,f"Permission Details Was Updated for {permission_updated_for.name}")
                    else:
                        messages.info(request,f"Something Went Wrong! Please Contact System Administrator about this issue")

                if request.POST.get('access_remove'):
                    '''To remove record from data access table'''
                    
                    ieeeId=request.POST['access_ieee_id']
                    if(FinanceAndCorporateTeam.remove_member_from_manage_team_access(ieee_id=ieeeId)):
                        messages.info(request,"Removed member from Managing Team")
                        return redirect('finance_and_corporate_team:manage_team')
                    else:
                        messages.info(request,"Something went wrong!")

                if request.POST.get('update_data_access_member'):
                    
                    new_data_access_member_list=request.POST.getlist('member_select')
                    
                    if(len(new_data_access_member_list)>0):
                        for ieeeID in new_data_access_member_list:
                            if(FinanceAndCorporateTeam.add_member_to_manage_team_access(ieeeID)=="exists"):
                                messages.info(request,f"The member with IEEE Id: {ieeeID} already exists in the Data Access Table")
                            elif(FinanceAndCorporateTeam.add_member_to_manage_team_access(ieeeID)==False):
                                messages.info(request,"Something Went wrong! Please try again")
                            elif(FinanceAndCorporateTeam.add_member_to_manage_team_access(ieeeID)==True):
                                messages.info(request,f"Member with {ieeeID} was added to the team table!")
                                return redirect('finance_and_corporate_team:manage_team')

            context={
                'data_access':data_access,
                'members':team_members,
                'insb_members':all_insb_members,
                'positions':position,
                'user_data':user_data,
                'all_sc_ag':sc_ag,
            }

            return render(request,"finance_and_corporate_team/manage_team.html",context=context)
        else:
            return render(request,"finance_and_corporate_team/access_denied.html", {'all_sc_ag':sc_ag ,'user_data':user_data,})
        
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    

def budgetHomePage(request):
    try:
        sc_ag=PortData.get_all_sc_ag(request=request)
        current_user=renderData.LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file

        eb_common_access = Branch_View_Access.common_access(request.user.username)
        has_access = FCT_Render_Access.get_common_access(request)


        if has_access:      
            if request.method == 'POST':
                ieee_ids = request.POST.getlist('ieee_id')
                access_types = request.POST.getlist('access_type')
                sheet_id = request.POST.get('sheet_id')

                if FinanceAndCorporateTeam.update_budget_sheet_access(sheet_id, ieee_ids, access_types):
                    messages.success(request, 'Budget sheet access updated!')
                else:
                    messages.warning(request, 'Could not update budget sheet access!')
                return redirect('finance_and_corporate_team:budgetHomePage')

            all_budget_sheets = BudgetSheet.objects.filter(sheet_of__primary=1)

            context={
                    'user_data':user_data,
                    'all_sc_ag':sc_ag,
                    'all_budget_sheets':all_budget_sheets,
                    'eb_common_access':eb_common_access
                }
            return render(request,"finance_and_corporate_team/budgetHomePage.html",context=context)
        else:
            return render(request,"finance_and_corporate_team/access_denied.html", {'all_sc_ag':sc_ag ,'user_data':user_data,})

    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
def event_page(request):

    try:

        sc_ag=PortData.get_all_sc_ag(request=request)
        current_user=renderData.LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        '''Only events organised by INSB would be shown on the event page of Graphics Team
        So, only those events are being retrieved from database'''
        insb_organised_events = Branch.load_insb_organised_events()
    
        context = {
            'all_sc_ag':sc_ag,
            'events_of_insb_only':insb_organised_events,
            'user_data':user_data,
        }


        return render(request,"Events/finance_and_corporate_team_events.html",context)
    
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)
    
@login_required
@member_login_permission
def create_budget(request, event_id=None):

    try:
        sc_ag=PortData.get_all_sc_ag(request=request)
        current_user=renderData.LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
    
        has_access = FCT_Render_Access.access_for_create_budget(request) or FCT_Render_Access.access_for_budget(request, event_id=event_id)

        if has_access:
            if request.method == "POST":
                cst_item = request.POST.getlist('cst_item[]')
                cst_quantity = request.POST.getlist('cst_quantity[]')
                cst_upc_bdt = request.POST.getlist('cst_upc_bdt[]')
                cst_total = request.POST.getlist('cst_total[]')

                rev_item = request.POST.getlist('rev_item[]')
                rev_quantity = request.POST.getlist('rev_quantity[]')
                rev_upc_bdt = request.POST.getlist('rev_upc_bdt[]')
                rev_total = request.POST.getlist('rev_total[]')

                budget_sheet = FinanceAndCorporateTeam.create_budget(request, event_id, cst_item, cst_quantity, cst_upc_bdt, cst_total, rev_item, rev_quantity, rev_upc_bdt, rev_total)
                
                if budget_sheet:
                    messages.success(request, 'Budget created successfully!')
                    return redirect('finance_and_corporate_team:edit_budget', budget_sheet.pk)
                else:
                    messages.warning(request, 'Could not create the budget!')
                    return redirect('finance_and_corporate_team:event_page')

            event = None
            if event_id:
                if BudgetSheet.objects.filter(event=event_id).count() > 0:
                    budget_sheet = BudgetSheet.objects.get(event=event_id)
                    return redirect('finance_and_corporate_team:edit_budget', budget_sheet.pk)
                
                elif Events.objects.filter(id=event_id).count() == 0:
                    messages.warning(request, 'Event does not exist!')
                    return redirect('finance_and_corporate_team:event_page')
                
                else:
                    event = Events.objects.get(id=event_id)

            context = {
                'all_sc_ag':sc_ag,
                'user_data':user_data,
                'access_type':'Edit',
                'event':event,
                'eb_common_access':False
            }

            return render(request,"finance_and_corporate_team/budgetPage.html", context)
        else:
            return render(request,"finance_and_corporate_team/access_denied.html", {'all_sc_ag':sc_ag ,'user_data':user_data,})

    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def edit_budget(request, sheet_id):

    try:
        sc_ag=PortData.get_all_sc_ag(request=request)
        current_user=renderData.LoggedinUser(request.user) #Creating an Object of logged in user with current users credentials
        user_data=current_user.getUserData() #getting user data as dictionary file
        
        eb_common_access = Branch_View_Access.common_access(request.user.username)
        access_type = FCT_Render_Access.access_for_budget(request, sheet_id)

        usd_rate = None
        if access_type == 'Edit':
            if request.method == "POST":
                if 'save_budget' in request.POST:
                    cst_item = request.POST.getlist('cst_item[]')
                    cst_quantity = request.POST.getlist('cst_quantity[]')
                    cst_upc_bdt = request.POST.getlist('cst_upc_bdt[]')
                    cst_total = request.POST.getlist('cst_total[]')

                    rev_item = request.POST.getlist('rev_item[]')
                    rev_quantity = request.POST.getlist('rev_quantity[]')
                    rev_upc_bdt = request.POST.getlist('rev_upc_bdt[]')
                    rev_total = request.POST.getlist('rev_total[]')

                    saved_rate = request.POST.get('saved_rate')
                    show_usd_rates = request.POST.get('show_usd_rates')

                    if FinanceAndCorporateTeam.edit_budget(sheet_id, cst_item, cst_quantity, cst_upc_bdt, cst_total, rev_item, rev_quantity, rev_upc_bdt, rev_total, saved_rate, show_usd_rates):           
                        messages.success(request, 'Budget updated successfully!')
                        return redirect('finance_and_corporate_team:edit_budget', sheet_id)
                    else:
                        messages.warning(request, 'Could not update budget!')
                        return redirect('finance_and_corporate_team:edit_budget', sheet_id)
                    
                elif 'save_access' in request.POST:
                    ieee_ids = request.POST.getlist('ieee_id')
                    access_types = request.POST.getlist('access_type')

                    if FinanceAndCorporateTeam.update_budget_sheet_access(sheet_id, ieee_ids, access_types):
                        messages.success(request, 'Budget sheet access updated!')
                    else:
                        messages.warning(request, 'Could not update budget sheet access!')
                    return redirect('finance_and_corporate_team:edit_budget', sheet_id)
                
            
            currency_data_response = requests.get('https://latest.currency-api.pages.dev/v1/currencies/usd.min.json')
            if(currency_data_response.status_code==200):
                # if response is okay then load data
                usd_rate = round(json.loads(currency_data_response.text)['usd']['bdt'],2)
            else:
                usd_rate = None

        
        fct_team_member_accesses = []
        if eb_common_access:
            fct_team_members = Branch.load_team_members(team_primary=11)

            for member in fct_team_members:
                access = BudgetSheetAccess.objects.filter(sheet_id=sheet_id, member=member)
                member_access_type = access[0].access_type if access.exists() else None

                fct_team_member_accesses.append({
                    'member': {
                        'ieee_id':member.ieee_id,
                        'name': member.name,
                        'position': member.position.role
                    },
                    'access_type': member_access_type
                })
                
        if access_type == 'Edit' or access_type == 'ViewOnly':
            
            try:
                budget_sheet = BudgetSheet.objects.get(id=sheet_id)
            except:
                messages.warning(request, 'Budget sheet does not exist!')
                return redirect('finance_and_corporate_team:event_page')
            
            deficit = 0.0
            surplus = 0.0

            if budget_sheet.total_cost > budget_sheet.total_revenue:
                deficit = budget_sheet.total_revenue - budget_sheet.total_cost
            elif budget_sheet.total_cost < budget_sheet.total_revenue:
                surplus = budget_sheet.total_revenue - budget_sheet.total_cost

            context = {
                'all_sc_ag':sc_ag,
                'user_data':user_data,
                'budget_sheet':budget_sheet,
                'access_type':access_type,
                'deficit':deficit,
                'surplus':surplus,
                'eb_common_access':eb_common_access,
                'fct_team_member_accesses':fct_team_member_accesses,
                'usd_rate':usd_rate
            }

            return render(request,"finance_and_corporate_team/budgetPage.html", context)
        else:
            return render(request,"finance_and_corporate_team/access_denied.html", {'all_sc_ag':sc_ag ,'user_data':user_data,})
    
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

@login_required
@member_login_permission
def download_budget(request):
    
    try:
        if request.method == 'GET':
            if request.GET.get('sheet_id'):
                sheet_id = request.GET.get('sheet_id')
                has_access = FCT_Render_Access.access_for_budget(request, sheet_id)

                if has_access == 'Edit' or has_access == 'ViewOnly':
                    budget_sheet = BudgetSheet.objects.filter(id=sheet_id)
                    if budget_sheet.exists():
                        budget_sheet = budget_sheet[0]
                        if request.GET.get('download_type') == 'pdf':
                            file = BudgetPDF.create_pdf(budget_sheet.sheet_of.primary, budget_sheet.name, budget_sheet.costBreakdownData, budget_sheet.revenueBreakdownData, budget_sheet.show_usd_rates)
                            
                            # Create response with PDF as attachment
                            response = HttpResponse(file, content_type='application/pdf')
                            response['Content-Disposition'] = f'inline; filename="{budget_sheet.name}.pdf"'

                            return response
                        elif request.GET.get('download_type') == 'excel':
                            # Example dummy data to test
                            # budget_data_example = {
                            #     "approval": "Dr. Fariah Mahzabeen & Shaira Imtiaz Aurchi",
                            # }

                            file = BudgetPDF.export_budget_sheet_to_excel(1, budget_sheet.name, budget_sheet.costBreakdownData, budget_sheet.revenueBreakdownData, budget_sheet.total_cost, budget_sheet.total_revenue)

                            # Create response with PDF as attachment
                            response = HttpResponse(file, content_type='application/vnd.ms-excel')
                            response['Content-Disposition'] = f'inline; filename="{budget_sheet.name}.xls"'

                            return response
                    else:
                        messages.warning(request, 'Budget Sheet does not Exist')
                        return redirect('finance_and_corporate_team:event_page')
                else:
                    return redirect('finance_and_corporate_team:edit_budget', sheet_id)
    except Exception as e:
        logger.error("An error occurred at {datetime}".format(datetime=datetime.now()), exc_info=True)
        ErrorHandling.saveSystemErrors(error_name=e,error_traceback=traceback.format_exc())
        return cv.custom_500(request)

class GetBudgetSheetAcessDataAjax(View):
    def get(self, request):
        if request.GET.get('sheet_id'):
            sheet_id = request.GET.get('sheet_id')
            fct_team_members = Branch.load_team_members(team_primary=11)
            fct_team_member_accesses = []

            fct_team_member_accesses.append({'sheet_id':sheet_id})

            for member in fct_team_members:
                access = BudgetSheetAccess.objects.filter(sheet_id=sheet_id, member=member)
                access_type = access[0].access_type if access.exists() else None

                fct_team_member_accesses.append({
                    'member': {
                        'ieee_id':member.ieee_id,
                        'name': member.name,
                        'position': member.position.role
                    },
                    'access_type': access_type
                })
            
            return JsonResponse({'data':fct_team_member_accesses})
        else:
            return JsonResponse({'message':'error'})
        