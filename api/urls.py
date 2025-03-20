# File: api/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('protected-resource/', views.protected_resource, name='protected-resource'),
    #path('create-expiring-token/', views.create_expiring_token, name='create-expiring-token'),
    #path('check-token-expired/', views.check_token_expired, name='check-token-expired'),
    #path('expire-session/', views.expire_session, name='expire-session'),
]