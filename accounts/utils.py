from django.utils import timezone
from django.conf import settings

import requests, jwt, os, datetime, logging
from uuid import uuid4

logger = logging.getLogger(__name__)



def get_NexusUser_profile_image_upload_path(instance, filename):
    """Generate a unique path for user profile images."""
    upload_to = 'user_profile_images'
    ext = filename.split('.')[-1]  # Extract file extension
    uuid = uuid4().hex  # Generate a unique filename
    user_identifier = instance.username if instance else "anonymous"
    
    new_filename = f'{user_identifier}_{uuid}.{ext}'
    return os.path.join(upload_to, new_filename)

########################################################
#           APPLE OAUTH (Sign in with apple)           #
########################################################
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

    data = response.json()  
    expected_keys = ["access_token", "token_type", "expires_in", "refresh_token", "id_token"]
    non_existing_keys = [k for k in expected_keys if k not in data]

    if len(non_existing_keys) != 0:
        raise ValueError({
            'error' : '[' + ', '.join(non_existing_keys) + ']' + " are not included in the grant response.",
            'reponse.json()' : data
        })

    return data

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
        Validate the signature and returns decoded id_token as dictionary.
        The id_token(decoded) should include ['sub', 'email'].
    """
    apple_keys = get_apple_public_key()
    header = jwt.get_unverified_header(id_token)
    
    key = next((k for k in apple_keys['keys'] if k['kid'] == header['kid']), None)
    if not key:
        raise ValueError({'error' : "Invalid Apple ID token: Public key not found"})
    
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
    decoded_token = jwt.decode(id_token, public_key, algorithms=["RS256"], audience=client_id, issuer="https://appleid.apple.com")

    expected_keys = ['sub', 'email']
    non_existing_keys = [k for k in expected_keys if k not in decoded_token]
    if len(non_existing_keys) != 0:
        raise ValueError({
            'error' : '[' + ', '.join(non_existing_keys) + ']' + " are not included in the 'id_token'.",
            'reponse.json()' : data
        })
    
    return decoded_token  # Returns a dictionary of user info
    