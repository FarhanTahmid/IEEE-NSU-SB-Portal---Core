
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal
import json
import logging
import os
from django.utils.timezone import localtime, is_aware
import traceback

import pytz
from central_branch.view_access import Branch_View_Access
from central_events.models import Events
from chapters_and_affinity_group.manage_access import SC_Ag_Render_Access
from insb_port import settings
from port.models import Chapters_Society_and_Affinity_Groups, Panels
from system_administration.system_error_handling import ErrorHandling
from wallet.models import Wallet, WalletEntry, WalletEntryFile, WalletEventStatus
from django.db.models import Sum, Case, When, F, Value, DecimalField, Min, Max, Subquery, OuterRef, IntegerField, Q, Count, DateTimeField
from django.db.models.functions import TruncDate, TruncMonth, TruncDay, Cast
from calendar import monthrange 

logger=logging.getLogger(__name__)      

class WalletManager:

    def add_wallet_entry(primary, entry_type, entry_date_time, entry_amount, name, contact, entry_remark, payment_mode, entry_categories, entry_files, event_id):
        
        try:
            sc_ag = Chapters_Society_and_Affinity_Groups.objects.filter(primary=primary).values('id')[0]['id']

            categories = str(entry_categories).split(',')

            event = None
            if event_id:
                event = Events.objects.get(id=event_id)

            wallet_entry = WalletEntry.objects.create(
                                    entry_date_time=entry_date_time,
                                    amount=entry_amount,
                                    name=name,
                                    contact=contact,
                                    remarks=entry_remark,
                                    payment_mode=payment_mode,
                                    entry_type=entry_type,
                                    entry_event=event,
                                    sc_ag_id=sc_ag,
                                    tenure=Panels.objects.get(panel_of=sc_ag, current=True))
            
            wallet_entry.categories.add(*categories)

            wallet = Wallet.objects.get(sc_ag=sc_ag)
            if wallet_entry.entry_type == 'CASH_IN':
                wallet.balance += Decimal(wallet_entry.amount)
            elif wallet_entry.entry_type == 'CASH_OUT':
                wallet.balance -= Decimal(wallet_entry.amount)
            wallet.save()
            
            for file in entry_files:
                WalletEntryFile.objects.create(wallet_entry=wallet_entry, document=file)

            if event_id:
                if not WalletEventStatus.objects.filter(wallet_event=event).exists():
                    WalletEventStatus.objects.create(wallet_event=event)
            
            return True
        except:
            return False

    def update_wallet_entry(entry_id, entry_date_time, entry_amount, name, contact, entry_remark, payment_mode, entry_categories, entry_files):

        try:
            categories = str(entry_categories).split(',')

            wallet_entry = WalletEntry.objects.get(id=entry_id)
            wallet_entry.entry_date_time = entry_date_time
            wallet_entry.name = name
            wallet_entry.contact = contact
            wallet_entry.remarks = entry_remark
            wallet_entry.payment_mode = payment_mode

            if wallet_entry.amount != Decimal(entry_amount):
                wallet = Wallet.objects.get(sc_ag=wallet_entry.sc_ag)
                if wallet_entry.entry_type == 'CASH_IN':
                    wallet.balance -= Decimal(wallet_entry.amount)
                    wallet_entry.amount = entry_amount
                    wallet.balance += Decimal(wallet_entry.amount)
                elif wallet_entry.entry_type == 'CASH_OUT':
                    wallet.balance += Decimal(wallet_entry.amount)
                    wallet_entry.amount = entry_amount
                    wallet.balance -= Decimal(wallet_entry.amount)

                wallet.save()

            wallet_entry.save()
            wallet_entry.categories.clear()
            wallet_entry.categories.add(*categories)

            for file in entry_files:
                WalletEntryFile.objects.create(wallet_entry=wallet_entry, document=file)
            return True
        except:
            return False


    def delete_wallet_entry(entry_id):

        try:
            wallet_entry = WalletEntry.objects.get(id=entry_id)
            wallet_entry_files = WalletEntryFile.objects.filter(wallet_entry=wallet_entry)
            
            for file in wallet_entry_files:
                path = settings.MEDIA_ROOT+str(file.document)
                if os.path.exists(path):
                    os.remove(path)
                file.delete()

            wallet_event_status = WalletEventStatus.objects.filter(wallet_event=wallet_entry.entry_event)
            if wallet_event_status.exists():
                wallet_event_status.delete()

            wallet = Wallet.objects.get(sc_ag=wallet_entry.sc_ag)
            if wallet_entry.entry_type == 'CASH_IN':
                wallet.balance -= Decimal(wallet_entry.amount)
            elif wallet_entry.entry_type == 'CASH_OUT':
                wallet.balance += Decimal(wallet_entry.amount)

            wallet.save()
            wallet_entry.delete()

            return True
        except:
            return False

    def delete_entry_file(file_id):

        try:
            entry_file = WalletEntryFile.objects.get(id=file_id)
            
            path = settings.MEDIA_ROOT+str(entry_file.document)
            if os.path.exists(path):
                os.remove(path)
            entry_file.delete()
            return True
        except:
            return False

    def has_access(request, primary, event_id=None, entry_id=None):
        username = request.user.username
        
        if primary == None:
            if Branch_View_Access.common_access(username):
                sc_ag = Chapters_Society_and_Affinity_Groups.objects.filter(primary=1).values('id')[0]['id']

                if event_id:
                    organiser = Events.objects.filter(id=event_id).values('event_organiser')[0]['event_organiser']
                    if organiser == sc_ag:
                        return True
                    else:
                        return False
                elif entry_id:
                    entry_owner = WalletEntry.objects.filter(id=entry_id).values('sc_ag')[0]['sc_ag']
                    if entry_owner == sc_ag:
                        return True
                    else:
                        return False
                return True
            else:
                return False
        elif primary == '1' or primary == 1:
            return False
        else:
            if SC_Ag_Render_Access.get_sc_ag_common_access_non_branch(request, primary):
                sc_ag = Chapters_Society_and_Affinity_Groups.objects.filter(primary=primary).values('id')[0]['id']

                if event_id:
                    organiser = Events.objects.filter(id=event_id).values('event_organiser')[0]['event_organiser']
                    if organiser == sc_ag:
                        return True
                    else:
                        return False
                elif entry_id:
                    entry_owner = WalletEntry.objects.filter(id=entry_id).values('sc_ag')[0]['sc_ag']
                    if entry_owner == sc_ag:
                        return True
                    else:
                        return False
                return True
            else:
                return False
            
    def get_wallet_entry_stats_whole_tenure(primary):
        stats = WalletEntry.objects.filter(
                tenure_id=Panels.objects.filter(panel_of=Chapters_Society_and_Affinity_Groups.objects.filter(primary=primary).values('id')[0]['id'], current=True).values('id')[0]['id'],
                sc_ag_id=Chapters_Society_and_Affinity_Groups.objects.filter(primary=primary).values('id')[0]['id']
            ).aggregate(
                total_entries=Count('id'),
                total_cash_in=Sum('amount', filter=Q(entry_type='CASH_IN')),
                total_cash_out=Sum('amount', filter=Q(entry_type='CASH_OUT'))
            )
        
        return stats
    
    def get_wallet_entry_stats_whole_tenure_by_month(primary):
        
        now = datetime.now()

        # Start of the current month
        start = datetime(now.year, 1, 1)

        # Compute the first day of the next month
        if now.month == 12:
            next_month = datetime(now.year + 1, 1, 1)
        else:
            next_month = datetime(now.year, now.month + 1, 1)

        # End of the current month = one second before the next month starts
        end = next_month - timedelta(seconds=1)

        # Fetch monthly cash in/out data
        raw_entries = WalletEntry.objects.filter(
            tenure_id=Panels.objects.filter(panel_of=Chapters_Society_and_Affinity_Groups.objects.filter(primary=primary).values('id')[0]['id'], current=True).values('id')[0]['id'],
            sc_ag_id=Chapters_Society_and_Affinity_Groups.objects.filter(primary=primary).values('id')[0]['id'],
            entry_date_time__range=(start, end)
        ).values('entry_date_time').annotate(
            cash_in=Sum('amount', filter=Q(entry_type='CASH_IN')),
            cash_out=Sum('amount', filter=Q(entry_type='CASH_OUT'))
        ).order_by('entry_date_time__month')

        data_by_month = {}
        for entry in raw_entries:
            month_number = entry['entry_date_time'].month  # 'month' is already a datetime object from TruncMonth
            data_by_month[month_number] = entry

        wallet_entry_stats_whole_tenure_by_month = []
        for month in range(1, 13):
            wallet_entry_stats_whole_tenure_by_month.append({
                'month': datetime(now.year, month, 1),
                'cash_in': data_by_month.get(month, {}).get('cash_in', 0),
                'cash_out': data_by_month.get(month, {}).get('cash_out', 0),
            })

        return wallet_entry_stats_whole_tenure_by_month

    def get_wallet_entry_stats_for_current_month(primary):

        now = datetime.now()

        # Start of the current month
        start = datetime(now.year, now.month, 1)

        # Compute the first day of the next month
        if now.month == 12:
            next_month = datetime(now.year + 1, 1, 1)
        else:
            next_month = datetime(now.year, now.month + 1, 1)

        # End of the current month = one second before the next month starts
        end = next_month - timedelta(seconds=1)

        # Fetch daily entries for the current month
        entries = WalletEntry.objects.filter(
            tenure_id=Panels.objects.filter(panel_of=Chapters_Society_and_Affinity_Groups.objects.filter(primary=primary).values('id')[0]['id'], current=True).values('id')[0]['id'],
            sc_ag_id=Chapters_Society_and_Affinity_Groups.objects.filter(primary=primary).values('id')[0]['id'],
            entry_date_time__range=(start, end)
        )
        daily_data = defaultdict(lambda: {'cash_in': 0, 'cash_out': 0})

        for entry in entries:
            # Convert to local time if needed
            dt = localtime(entry.entry_date_time) if is_aware(entry.entry_date_time) else entry.entry_date_time
            day = dt.replace(hour=0, minute=0, second=0, microsecond=0)

            if entry.entry_type == 'CASH_IN':
                daily_data[day]['cash_in'] += entry.amount
            elif entry.entry_type == 'CASH_OUT':
                daily_data[day]['cash_out'] += entry.amount

        # Step 4: Return as sorted list of dicts
        return [
            {'day': day, 'cash_in': data['cash_in'], 'cash_out': data['cash_out']}
            for day, data in sorted(daily_data.items())
        ]