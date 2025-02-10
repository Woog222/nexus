from django.urls import path

from .views import AppleOauthView, NexusUserAPIView, RefreshTokenAPIView



urlpatterns = [
    path('oauth/apple/callback/', AppleOauthView.as_view(), name = 'apple-callback'),
    path('<str:user_id>/', NexusUserAPIView.as_view(), name = 'user-detail'),
    path('auth/refresh/', RefreshTokenAPIView.as_view(), name="token-refresh"),
    # path('login/', login_view, name='login' ),
]

