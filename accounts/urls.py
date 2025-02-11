from django.urls import path

from .views import AppleOauthView, NexusUserRetrieveView, NexusUserUpdateView
from rest_framework_simplejwt.views import (
    #TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('oauth/apple/callback/', AppleOauthView.as_view(), name = 'apple-callback'),
    path('', NexusUserRetrieveView.as_view(), name = 'user-detail'),
    path('update/', NexusUserUpdateView.as_view(), name = 'user-update'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name = 'token-refresh'),
]

