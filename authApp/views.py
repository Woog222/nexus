from allauth.socialaccount.providers.apple.views import AppleOAuth2Adapter
from allauth.socialaccount.providers.apple.client import AppleOAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.conf import settings
from rest_framework import response, status
from django.shortcuts import redirect

import logging

from .customs.apple import (
    CustomAppleOAuth2Client,
    CustomAppleOAuth2Adapter,
    CustomAppleLoginSerializer
)


logger = logging.getLogger(__name__)

class AppleLoginView(SocialLoginView):
    callback_url = settings.APPLE_REDIRECT_URI
    adapter_class = CustomAppleOAuth2Adapter
    client_class = CustomAppleOAuth2Client
    serializer_class = CustomAppleLoginSerializer

    def post(self, request, *args, **kwargs):
        try:
            return super().post(request, *args, **kwargs)
        except Exception as e:
            return response.Response(status=status.HTTP_400_BAD_REQUEST, data=str(e))

class AppleWebCallbackView(SocialLoginView):
    callback_url = settings.APPLE_REDIRECT_URI
    adapter_class = CustomAppleOAuth2Adapter
    client_class = CustomAppleOAuth2Client
    serializer_class = CustomAppleLoginSerializer

    fe_redirect_uri = "https://nexus-webxr.vercel.app/"

    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            logger.debug(f"[AppleWebCallbackView] response.data: {response.data}")

            token = response.data.get('access')
            redirect_response = redirect(f"{self.fe_redirect_uri}?token={token}")
            for key, value in response.cookies.items():
                logger.debug(f"[AppleWebCallbackView] cookie: {key} {value}")
                redirect_response.set_cookie(key, value.value, httponly=value.get('httponly', True), secure=value.get('secure', False))
            return redirect_response
        except Exception as e:
            return response.Response(status=status.HTTP_400_BAD_REQUEST, data=str(e))


class AppleLoginView_TEMP(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def get(self, reqeust):
        apple_base_url = "https://appleid.apple.com"
        apple_auth_url = f"{apple_base_url}/auth/authorize"
        client_id = settings.APPLE_CLIENT_ID
        redirect_uri = settings.APPLE_REDIRECT_URI

        uri = f"{apple_auth_url}?client_id={client_id}&&redirect_uri={redirect_uri}&response_type=code&response_mode=form_post"

        res = redirect(uri)
        return res
