from django.contrib import admin
from .models import *

# Register your models here.

admin.site.register(BudgetSheet)

admin.site.register(BudgetSheetAccess)

admin.site.register(BudgetSheetSignature)