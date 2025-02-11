from django.http import QueryDict
from django.conf import settings
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework.generics import RetrieveAPIView, UpdateAPIView
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status

import requests, logging, jwt, os
from datetime import timedelta
from dotenv import load_dotenv

from .serializers import NexusUserSerializer
from .models import NexusUser
from .utils import (
    generate_apple_client_secret, 
    exchange_apple_auth_code, 
    validate_apple_id_token,
)

logger = logging.getLogger(__name__)

class AppleOauthView(APIView):
    """ Handles Apple OAuth login callback and token exchange. """
    permission_classes = [AllowAny]

    APPLE_DATA = {
        'APPLE_CLIENT_ID' : settings.APPLE_CLIENT_ID,
        'APPLE_KEY_ID' : settings.APPLE_KEY_ID,
        'APPLE_TEAM_ID': settings.APPLE_TEAM_ID,
        'APPLE_REDIRECT_URI' : settings.APPLE_REDIRECT_URI,
        'APPLE_PUBLIC_KEY_URL' : settings.APPLE_PUBLIC_KEY_URL,
        'APPLE_TOKEN_URL' : settings.APPLE_TOKEN_URL,
        'APPLE_PRIVATE_KEY' : settings.APPLE_PRIVATE_KEY,
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
        user_id = f"{settings.APPLE_USER_ID_PREFIX}_{id_token_decoded.get("sub")}"
        email = id_token_decoded.get("email")
        apple_access_token = token_data.get("access_token")
        apple_refresh_token = token_data.get("refresh_token")

        user, created = NexusUser.objects.get_or_create(
            user_id=user_id, 
            defaults={
                "email": email,
                "apple_access_token": apple_access_token,
                "apple_refresh_token": apple_refresh_token,
            }
        )

        refresh = RefreshToken.for_user(user)
        return Response({
            "user_id" : user_id,
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "created" : "yes" if created else "no",
        }, status=status.HTTP_200_OK)


class NexusUserRetrieveView(RetrieveAPIView):
    queryset = NexusUser.objects.all()
    serializer_class = NexusUserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """Override get_object to enforce user ownership check."""
        user_id = str(self.request.user.user_id)  # Authenticated user from JWT
        return self.queryset.get(user_id=user_id)





class NexusUserUpdateView(UpdateAPIView):
    queryset = NexusUser.objects.all()
    serializer_class = NexusUserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """Override get_object to enforce user ownership check."""
        user_id = str(self.request.user.user_id)  # Authenticated user from JWT
        return self.queryset.get(user_id=user_id)
