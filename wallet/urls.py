from django.urls import path
from . import views

app_name = 'wallet'

urlpatterns = [   
    path('', views.wallet_homepage, name='wallet_homepage'),
    path('entries/<int:event_id>/', views.entries, name='entries_event'),
    path('entries/cash_in/', views.cash_in, name='cash_in'),
    path('entries/cash_in/<int:event_id>/', views.cash_in, name='cash_in_event'),
    path('entries/cash_out/', views.cash_out, name='cash_out'),
    path('entries/cash_out/<int:event_id>/', views.cash_out, name='cash_out_event'),
    path('entries/cash_edit/<int:entry_id>/', views.cash_edit, name='cash_edit'),
    path('entries/update_status/', views.WalletEventStatusUpdateAjax.as_view(), name='wallet_event_update_status'),
]
