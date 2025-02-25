from dotenv import load_dotenv
import os
import datetime


load_dotenv()

"""
JWT
"""
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')  

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES' : [
        'rest_framework.permissions.IsAuthenticated',
    ]
}

# SimpleJWT settings (Latest Configuration)
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': datetime.timedelta(days=1),  # 5 minutes
    'REFRESH_TOKEN_LIFETIME': datetime.timedelta(days=7),  # 7 days
    'ROTATE_REFRESH_TOKENS': True,  # Issue a new refresh token on use
    'BLACKLIST_AFTER_ROTATION': True,  # Blacklist old refresh tokens
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': JWT_SECRET_KEY,  # Use Django's SECRET_KEY
    'VERIFYING_KEY': None,
    'AUTH_HEADER_TYPES': ('Bearer',),  # Use "Bearer <token>" format
    'USER_ID_FIELD': 'username',
    'USER_ID_CLAIM': 'username',
    'TOKEN_TYPE_CLAIM': 'token_type',
    "TOKEN_OBTAIN_SERIALIZER": "accounts.serializers.MyTokenObtainPairSerializer",
    'JTI_CLAIM': 'jti',  # Unique token identifier
}


"""
APPLE 
"""
# Apple OAuth (Sign in with Apple)
APPLE_REDIRECT_URI = "https://www.cvan.shop/accounts/oauth/apple/callback/"
APPLE_PUBLIC_KEY_URL = "https://appleid.apple.com/auth/keys"
APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token"
APPLE_CLIENT_ID = os.getenv("APPLE_CLIENT_ID")
APPLE_KEY_ID = os.getenv("APPLE_KEY_ID")
APPLE_TEAM_ID= os.getenv("APPLE_TEAM_ID")
with open("accounts/private/apple_authkey.p8", "r") as f:
    APPLE_PRIVATE_KEY = f.read()


APPLE_USER_ID_PREFIX = "APPLE" # user id : {prefix}_{apple_sub}

