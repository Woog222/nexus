from django.urls import path

from .views import AppleOauthView

# from django.shortcuts import redirect
# import urllib.parse 
# def login_view(request):
#     apple_auth_url = "https://appleid.apple.com/auth/authorize"
    
#     params = {
#         "client_id": "com.cvan.shop",  # Apple App ID
#         "redirect_uri": "https://www.cvan.shop/accounts/oauth/apple/callback/",  # Callback URL
#         "response_type": "code id_token",  # Request both auth code & ID token
#         "scope": "email name",  # Request user's email and name
#         "response_mode": "form_post",  # Apple will send data via POST
#         "state": "random_string_for_csrf_protection",  # Prevent CSRF attacks
#     }
    
#     auth_url = f"{apple_auth_url}?{urllib.parse.urlencode(params)}"
#     return redirect(auth_url)

urlpatterns = [
    path('oauth/apple/callback/', AppleOauthView.as_view(), name = "apple_callback"),
    # path('login/', login_view, name="login" ),
]

