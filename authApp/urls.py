# auth/urls.py
from django.urls import path, include, re_path
from django.views.generic import TemplateView
from dj_rest_auth.registration.views import VerifyEmailView
from .views import AppleLoginView, AppleLoginView_TEMP, AppleWebCallbackView

urlpatterns = [
    path('django-allauth/', include('allauth.urls')),
    path('', include('dj_rest_auth.urls')),
    path('apple/callback/', AppleLoginView.as_view(), name='apple-callback'),
    path('apple/web-callback/', AppleWebCallbackView.as_view(), name='apple-web-callback'),
    path('apple/login/', AppleLoginView_TEMP.as_view(), name='apple-login'),
]

