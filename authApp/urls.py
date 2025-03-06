# auth/urls.py
from django.urls import path, include, re_path
from django.views.generic import TemplateView
from dj_rest_auth.registration.views import VerifyEmailView
from .views import AppleLoginView, AppleLoginView_TEMP

urlpatterns = [
    path('', include('dj_rest_auth.urls')),
    path('apple/callback/', AppleLoginView.as_view(), name='apple-callback'),
    path('apple/login/', AppleLoginView_TEMP.as_view(), name='apple-login'),
]

"""
path('registration/', include('dj_rest_auth.registration.urls')),

# this url is used to generate email content for password reset
re_path(
    r'^password-reset/confirm/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,32})/$',
    TemplateView.as_view(template_name="password_reset_confirm.html"),
    name='password_reset_confirm'
),

# path('account-confirm-email/', VerifyEmailView.as_view(), name='account_email_verification_sent'),
"""
