from django.http import QueryDict
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import requests
import jwt
import os
from datetime import timedelta
from django.utils import timezone
from django.conf import settings


class AppleOauthView(APIView):
    """Handles Apple OAuth login callback and token exchange."""
    
    APPLE_CLIENT_ID = os.getenv("APPLE_CLIENT_ID")
    APPLE_KEY_ID = os.getenv("APPLE_KEY_ID")
    APPLE_TEAM_ID= os.getenv("APPLE_TEAM_ID")
    APPLE_REDIRECT_URI = "https://www.cvan.shop/apple/redirected/"
    APPLE_PUBLIC_KEY_URL = "https://appleid.apple.com/auth/keys"
    APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token"


    def post(self, request, *args, **kwargs):
        # Parse the form data from request.body
        body = request.body.decode('utf-8')  # Convert bytes to string
        data = QueryDict(body)  # Parse the form data
        auth_code = data.get("code")  # Extract the 'code' value
        
        if not auth_code:
            return Response({"error": "Authorization code is missing"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Exchange authorization code for tokens
            token_data = self.exchange_apple_auth_code(auth_code)
            
            # Todo: Handle user sign up or login here based on the id_token
            
            return Response(token_data)  # Send the token data back as response
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    def exchange_apple_auth_code(self, auth_code: str):
        """Exchange Apple authorization code for access and identity tokens."""
        
        data = {
            "client_id": self.APPLE_CLIENT_ID,  # Your app's Bundle ID / Service ID
            "client_secret": self.generate_apple_client_secret(),
            "code": auth_code,
            "grant_type": "authorization_code",
            "redirect_uri": self.APPLE_REDIRECT_URI,  # If used in web flow
        }

        # Exchange the authorization code for tokens via Apple API
        response = requests.post(self.APPLE_TOKEN_URL, data=data)

        if response.status_code != 200:
            raise ValueError(f"Apple token exchange failed: {response.json()}")
        
        return response.json()  # Returns access_token, id_token, refresh_token

    def generate_apple_client_secret(self):
        """Generate JWT client_secret for Apple API authentication."""
        
        now = timezone.now()
        headers = {
            'kid': self.APPLE_KEY_ID  # Key ID for Apple's JWT signing
        }

        payload = {
            'iss': self.APPLE_TEAM_ID,  # Apple Developer Team ID
            'iat': now.timestamp(),
            'exp': (now + timedelta(days=180)).timestamp(),  # Valid for 180 days
            'aud': 'https://appleid.apple.com',
            'sub': self.APPLE_CLIENT_ID,  # Your App's Bundle ID / Service ID
        }

        client_secret = jwt.encode(
            payload,
            self.APPLE_PRIVATE_KEY,
            algorithm='ES256',
            headers=headers,
        )

        return client_secret
