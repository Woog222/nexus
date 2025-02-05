from django.http import QueryDict
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

import requests, logging, jwt, os
from datetime import timedelta
from dotenv import load_dotenv

from .utils import generate_apple_client_secret, exchange_apple_auth_code



load_dotenv()
logger = logging.getLogger(__name__)

class AppleOauthView(APIView):
    """ Handles Apple OAuth login callback and token exchange. """

    with open("accounts/private/apple_authkey.p8", "r") as f:
        APPLE_PRIVATE_KEY = f.read()
    APPLE_DATA = {
        'APPLE_CLIENT_ID' : os.getenv("APPLE_CLIENT_ID"),
        'APPLE_KEY_ID' : os.getenv("APPLE_KEY_ID"),
        'APPLE_TEAM_ID': os.getenv("APPLE_TEAM_ID"),
        'APPLE_REDIRECT_URI' : "https://www.cvan.shop/accounts/oauth/apple/callback/",
        'APPLE_PUBLIC_KEY_URL' : "https://appleid.apple.com/auth/keys",
        'APPLE_TOKEN_URL' : "https://appleid.apple.com/auth/token",
        'APPLE_PRIVATE_KEY' : APPLE_PRIVATE_KEY,
    }

    def post(self, request, *args, **kwargs):

        """
            STEP 1. Validate the authorization grant code
        """
        auth_code = request.data.get("code")
        if not auth_code:
            return Response({"error": "code is missing"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token_data = exchange_apple_auth_code(auth_code=auth_code, APPLE_DATA= self.APPLE_DATA)
            logger.debug(token_data)
            logger.debug(type(token_data))
            # Todo: Handle user sign up or login here based on the id_token
            return Response(token_data)  # Send the token data back as response
        except ValueError as e:
            logger.debug(str(e))
            return Response(e.args[0], status=status.HTTP_400_BAD_REQUEST)

        """
            STEP 2. 
            {
                "access_token": "a7f9eb52b7b70...",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "rf5430a91dadf...",
                "id_token": "eyJraWQiOiJyczBNM2t...
            } (dict)
        """
        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token')





