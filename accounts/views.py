from django.http import QueryDict
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

import requests, logging, jwt, os
from datetime import timedelta
from dotenv import load_dotenv

from .models import NexusUser
from .utils import (
    generate_apple_client_secret, 
    exchange_apple_auth_code, 
    validate_apple_id_token,
    create_access_token,
    create_refresh_token,
    refresh_access_token,
    validate_JWTtoken,
)


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
            STEP 1. Validate the authorization grant code and get a token data

            Example of a token data : 
            {
                "access_token": "a7f9eb52b7b70...",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "rf5430a91dadf...",
                "id_token": "eyJraWQiOiJyczBNM2t...
            } (dict)
        """
        auth_code = request.data.get("code")
        if not auth_code:
            return Response({"error": "code is missing"}, status=status.HTTP_400_BAD_REQUEST)

        
        try:
            token_data = exchange_apple_auth_code(auth_code=auth_code, APPLE_DATA= self.APPLE_DATA)
        except ValueError as e:
            return Response(e.args[0], status=status.HTTP_400_BAD_REQUEST)
        # The "token_data" is now ensured to have all keys commented above.

        """
            STEP 2. Validate and decode the id_token
        """

        
        try:
            id_token_decoded = validate_apple_id_token(
                id_token = token_data.get('id_token'), 
                client_id=self.APPLE_DATA.get('APPLE_CLIENT_ID')
            )
        except ValueError as e:
            return Response(e.args[0], status=status.HTTP_400_BAD_REQUEST)
        # The "id_token"_decoded is now ensured to have 'sub' and 'email'.
        """
            STEP 3. Issue JWT tokens and update user data.
        """
        user_id = id_token_decoded.get("sub")
        email = id_token_decoded.get("email")
        apple_access_token = token_data.get("access_token")
        apple_refresh_token = token_data.get("refresh_token")
        nexus_access_token = create_access_token(user_id = user_id, email=email)
        nexus_refresh_token = create_refresh_token(user_id = user_id)

        user, created = NexusUser.objects.update_or_create(
            user_id=user_id, 
            defaults={
                "email": email,
                "apple_access_token": apple_access_token,
                "apple_refresh_token": apple_refresh_token,
                "nexus_access_token": nexus_access_token,
                "nexus_refresh_token": nexus_refresh_token,
            }
        )

        return Response({
            'user_id' : user_id,
            'email' : email,
            'access_token' : nexus_access_token,
            'refresh_token' : nexus_refresh_token,
            'created' : 'yes' if created else 'no'
        }, status = HTTP_200_OK)

