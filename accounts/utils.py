from django.utils import timezone
from django.conf import settings

import requests, jwt, os, datetime
from dotenv import load_dotenv
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError



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
        'exp': (now + datetime.timedelta(days=180)).timestamp(),  # Valid for 180 days
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

def get_apple_public_key():
    apple_keys_url = "https://appleid.apple.com/auth/keys"
    response = requests.get(apple_keys_url)
    return response.json()  # Contains public keys

def validate_apple_id_token(id_token:str, client_id:str):
    """
        validate the signature and returns decoded id_token as dictionary
    """
    apple_keys = get_apple_public_key()
    header = jwt.get_unverified_header(id_token)
    
    key = next((k for k in apple_keys['keys'] if k['kid'] == header['kid']), None)
    if not key:
        raise ValueError({'error' : "Invalid Apple ID token: Public key not found"})
    
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
    decoded_token = jwt.decode(id_token, public_key, algorithms=["RS256"], audience=client_id, issuer="https://appleid.apple.com")
    
    return decoded_token  # Returns a dictionary of user info

#######################################################
#                    JWT Token Utils                  #
#######################################################
def create_access_token(user_id:str, email:str):
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),  # 1 hour
        "iat": datetime.datetime.utcnow(),
        "iss": "nexus"
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")

def create_refresh_token(user_id:str):
    payload = {
        "sub": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30),  # 30 days
        "iat": datetime.datetime.utcnow(),
        "iss": "nexus"
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")

def refresh_access_token(refresh_token:str, email:str="test@example.com"):
    """ 
    Returns a new access token.
    jwt.ExpiredSignatureError, jwt.InvalidTokenError are handled by caller.
    """
    decoded = jwt.decode(refresh_token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
    user_id = decoded["sub"]
    return create_access_token(user_id = user_id, email = email) # email="example@email.com")  )


def validate_access_token(token):
    """
    Validates an access token and return its decoded one.
    jwt.ExpiredSignatureError, jwt.InvalidTokenError are handled by caller.
    """
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])

