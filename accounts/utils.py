from django.utils import timezone

import requests, jwt, os
from datetime import timedelta
from dotenv import load_dotenv



def exchange_apple_auth_code(auth_code: str, APPLE_DATA: dict):
    """ 
    Exchange Apple authorization code for access and identity tokens.

    APPLE_DATA should include 
    ['APPLE_KEY_ID', 'APPLE_CLIENT_ID', 'APPLE_PRIVATE_KEY','APPLE_TEAM_ID', 'APPLE_TOKEN_URL', 'APPLE_REDIRECT_URI', 'APPLE_PUBLIC_KEY_URL']

    Expected response body:
    {
        "access_token": "a7f9eb52b7b70...",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "rf5430a91dadf...",
        "id_token": "eyJraWQiOiJyczBNM2t...
    }
    """
    client_secret = generate_apple_client_secret(
        APPLE_KEY_ID = APPLE_DATA.get('APPLE_KEY_ID'),
        APPLE_TEAM_ID = APPLE_DATA.get('APPLE_TEAM_ID'),
        APPLE_CLIENT_ID = APPLE_DATA.get('APPLE_CLIENT_ID'),
        APPLE_PRIVATE_KEY = APPLE_DATA.get('APPLE_PRIVATE_KEY'),
    )
    data = {
        "client_id": APPLE_DATA.get('APPLE_CLIENT_ID'),  # Your app's Bundle ID / Service ID
        "client_secret": client_secret,
        "code": auth_code,
        "grant_type": "authorization_code", # or "refresh_token"
        "redirect_uri": APPLE_DATA.get('APPLE_REDIRECT_URI'),  # If used in web flow
        # "refresh_token" : ..
    }

    # Exchange the authorization code for tokens via Apple API
    response = requests.post(APPLE_DATA.get('APPLE_TOKEN_URL'), data=data)
    if response.status_code != 200:
        raise ValueError(response.json())
    return response.json()  

def generate_apple_client_secret(
        APPLE_KEY_ID:str, 
        APPLE_TEAM_ID:str, 
        APPLE_CLIENT_ID:str, 
        APPLE_PRIVATE_KEY:str,
    ):
    """Generate JWT client_secret for Apple API authentication."""
    
    now = timezone.now()
    headers = {
        'kid': APPLE_KEY_ID  # Key ID for Apple's JWT signing
    }
    payload = {
        'iss': APPLE_TEAM_ID,  # Apple Developer Team ID
        'iat': now.timestamp(),
        'exp': (now + timedelta(days=180)).timestamp(),  # Valid for 180 days
        'aud': 'https://appleid.apple.com',
        'sub': APPLE_CLIENT_ID,  # Your App's Bundle ID / Service ID
    }
    client_secret = jwt.encode(
        payload = payload,
        key = APPLE_PRIVATE_KEY,
        algorithm='ES256',
        headers = headers,
    )
    return client_secret