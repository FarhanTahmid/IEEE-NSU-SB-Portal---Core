from django.db import models

from central_events.models import Events
from port.models import Chapters_Society_and_Affinity_Groups
from users.models import Members

# Create your models here.

class BudgetSheet(models.Model):

    name = models.CharField(null=False, blank=False, max_length=150, default='Untitled Budget Sheet')
    sheet_of = models.ForeignKey(Chapters_Society_and_Affinity_Groups, null=False, blank=False, on_delete=models.CASCADE)
    event = models.ForeignKey(Events, null=True, blank=True, on_delete=models.SET_NULL)
    costBreakdownData = models.JSONField(default=dict)
    revenueBreakdownData = models.JSONField(default=dict)
    total_cost = models.FloatField(null=False, blank=False, default=0.0)
    total_revenue = models.FloatField(null=False, blank=False, default=0.0)
    usd_rate = models.FloatField(null=True, blank=True, default=None)
    show_usd_rates = models.BooleanField(null=False, blank=False, default=False)
    approval_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = 'Budget Sheet'

    def __str__(self):
        return str(self.pk)
    
class BudgetSheetAccess(models.Model):

    sheet = models.ForeignKey(BudgetSheet, null=False, blank=False, on_delete=models.CASCADE)
    member = models.ForeignKey(Members, null=False, blank=False, on_delete=models.CASCADE)
    access_type = models.CharField(null=False, blank=False, max_length=20, choices=(('ViewOnly','ViewOnly'), ('Edit','Edit'), ('Restricted','Restricted')), default='Restricted')

    class Meta:
        verbose_name = 'Budget Sheet Access'

    def __str__(self):
        return self.member.name
    
class BudgetSheetSignature(models.Model):

    left_signature = models.TextField()
    right_signature = models.TextField()
    sc_ag = models.ForeignKey(Chapters_Society_and_Affinity_Groups, null=False, blank=False, on_delete=models.CASCADE)

    class Meta:
        verbose_name = 'Budget Sheet Signature'

    def __str__(self):
        return str(self.pk)