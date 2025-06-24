from django.contrib import admin
from .models import *

# Register your models here.
@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = ['sc_ag']

@admin.register(WalletEntryCategory)
class WalletEntryCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'background_colour', 'text_colour']

@admin.register(WalletEntry)
class WalletEntryAdmin(admin.ModelAdmin):
    list_display = ['id', 'sc_ag', 'creation_date_time', 'update_date_time', 'entry_date_time', 'entry_type', 'amount', 'payment_mode']

@admin.register(WalletEntryFile)
class WalletEntryFileAdmin(admin.ModelAdmin):
    list_display = ['id', 'wallet_entry', 'document']

@admin.register(WalletEventStatus)
class WalletEventStatusAdmin(admin.ModelAdmin):
    list_display = ['id', 'wallet_event', 'status']