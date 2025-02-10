from django.http import QueryDict
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
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
    create_access_token,
    create_refresh_token,
    refresh_access_token,
    validate_JWTtoken,
)


load_dotenv()
logger = logging.getLogger(__name__)

class AppleOauthView(APIView):
    """ Handles Apple OAuth login callback and token exchange. """

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
        user_id = f"{settings.APPLE_USER_ID_PREFIX}{id_token_decoded.get("sub")}"
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
            }
        )

        return Response({
            'user_id' : user_id,
            'email' : email,
            'access_token' : nexus_access_token,
            'refresh_token' : nexus_refresh_token,
            'created' : 'yes' if created else 'no'
        }, status = status.HTTP_200_OK)


class NexusUserAPIView(APIView):
    """
    API view to return user information.
    """

    def get(self, request, user_id):


        logger.debug(f"({user_id}) {request.headers}")

        """
        STEP 1. Validate the access_token
        """
        token = request.headers.get('Authorization')  # Get the Authorization header
        if not token:
            return Response({'error': 'Access token is missing'}, status=status.HTTP_401_UNAUTHORIZED)
        token = token.split(' ')[1]  # Remove the 'Bearer ' prefix

        try:
            # Decode and validate the JWT token
            decoded = validate_JWTtoken(token)
            user_id_from_token = decoded['user_id']  # Assuming 'user_id' holds the user_id

            if user_id_from_token != user_id:
                return Response({'error': 'Invalid token for this user'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': str(e)}, status = status.HTTP_401_UNAUTHORIZED)

        """
        STEP 2. Returns the user information.
        """
        try:
            # Fetch user by ID
            user = NexusUser.objects.get(user_id=user_id)
            serializer = NexusUserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except NexusUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)




class RefreshTokenAPIView(APIView):
    """
    API view to refresh an access token using a refresh token.
    request body: {'request_token' : '...'}
    response body: {'access_token' : '...'}
    """

    def post(self, request):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Call the refresh function
            new_access_token = refresh_access_token(refresh_token)
            return Response({'access_token': new_access_token }, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({'error': 'Refresh token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
