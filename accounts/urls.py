from django.urls import path
from .views import AppleOauthView

urlpatterns = [
    path('oauth/apple/callback', AppleOauthView.as_view(), name = "apple_callback"),
]
