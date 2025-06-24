from django.utils import timezone
import os
from django.db import models

from central_events.models import Events
from port.models import Chapters_Society_and_Affinity_Groups, Panels

# Create your models here.

class Wallet(models.Model):

    sc_ag = models.ForeignKey(Chapters_Society_and_Affinity_Groups, null=False, blank=False, on_delete=models.DO_NOTHING)
    balance = models.DecimalField(null=False, blank=False, max_digits=10, decimal_places=2, default=0.0)

    class Meta:
        verbose_name = 'Wallet'

    def __str__(self) -> str:
        return str(self.sc_ag)

class WalletEntryCategory(models.Model):

    name = models.CharField(null=False, blank=False, max_length=12)
    background_colour = models.CharField(null=False, blank=False, max_length=9, default='#FF9500')
    text_colour = models.CharField(null=False, blank=False, max_length=9, default='#FF9500')

    class Meta:
        verbose_name = 'Wallet Entry Category'

    def __str__(self) -> str:
        return self.name

class WalletEntry(models.Model):

    creation_date_time = models.DateTimeField(null=False, blank=False, auto_now_add=True)
    update_date_time = models.DateTimeField(null=False, blank=False, auto_now=True)
    entry_date_time = models.DateTimeField(null=False, blank=False, default=timezone.now)
    entry_event = models.ForeignKey(Events, null=True, blank=True, on_delete=models.SET_NULL)
    entry_type = models.CharField(null=False, blank=False, max_length=12, default='NOT_SET', choices=[
        ('CASH_IN', 'Cash In'),
        ('CASH_OUT', 'Cash Out'),
        ('NOT_SET', 'NOT SET'),
    ])
    amount = models.DecimalField(null=False, blank=False, max_digits=9, decimal_places=2, default=0.0)
    name = models.CharField(null=True, blank=True, max_length=40)
    contact = models.CharField(null=True, blank=True, max_length=40)
    remarks = models.TextField(null=False, blank=False)
    categories = models.ManyToManyField(WalletEntryCategory, related_name='wallet_entries')
    payment_mode = models.CharField(null=True, blank=True, max_length=20, default='CASH', choices=[
        ('CASH', 'Cash'),
        ('CARD', 'Card'),
        ('BKASH', 'Bkash'),
        ('NAGAD', 'Nagad'),
    ])

    sc_ag = models.ForeignKey(Chapters_Society_and_Affinity_Groups, null=False, blank=False, on_delete=models.DO_NOTHING)
    tenure = models.ForeignKey(Panels, null=False, blank=False, on_delete=models.DO_NOTHING)

    class Meta:
        verbose_name = 'Wallet Entry'

    def __str__(self) -> str:
        return str(self.pk)


class WalletEntryFile(models.Model):

    wallet_entry = models.ForeignKey(WalletEntry, null=True, blank=True, on_delete=models.SET_NULL)
    document = models.FileField(null=True,blank=True,upload_to="Wallet/Wallet_Documents/")

    class Meta:
        verbose_name = 'Wallet Entry File'

    def __str__(self) -> str:
        return str(self.pk)
    
    @property
    def filename(self) -> str:
        return os.path.basename(self.document.path)
    
class WalletEventStatus(models.Model):

    wallet_event = models.ForeignKey(Events, null=False, blank=False, on_delete=models.CASCADE)
    status = models.CharField(null=False, blank=False, max_length=12, default='ONGOING', choices=[
        ('ONGOING', 'Ongoing'),
        ('COMPLETED', 'Completed'),
    ])

    class Meta:
        verbose_name = 'Wallet Event Status'

    def __str__(self) -> str:
        return str(self.pk)