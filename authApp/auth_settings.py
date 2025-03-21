from dotenv import load_dotenv
import os
from datetime import timedelta


load_dotenv()

"""
JWT (django-rest-framework-simplejwt)
"""
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')  
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": False,

    "ALGORITHM": "HS256",
    "SIGNING_KEY": JWT_SECRET_KEY,
    "VERIFYING_KEY": "",
    "AUDIENCE": None,
    "ISSUER": None,
    "JSON_ENCODER": None,
    "JWK_URL": None,
    "LEEWAY": 0,

    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    'USER_ID_FIELD': 'username',
    'USER_ID_CLAIM': 'username',
    "USER_AUTHENTICATION_RULE": "rest_framework_simplejwt.authentication.default_user_authentication_rule",

    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "TOKEN_USER_CLASS": "rest_framework_simplejwt.models.TokenUser",

    "JTI_CLAIM": "jti",

    "SLIDING_TOKEN_REFRESH_EXP_CLAIM": "refresh_exp",
    "SLIDING_TOKEN_LIFETIME": timedelta(minutes=5),
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=1),

    "TOKEN_OBTAIN_SERIALIZER": "accounts.serializers.MyTokenObtainPairSerializer",
    "TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSerializer",
    "TOKEN_VERIFY_SERIALIZER": "rest_framework_simplejwt.serializers.TokenVerifySerializer",
    "TOKEN_BLACKLIST_SERIALIZER": "rest_framework_simplejwt.serializers.TokenBlacklistSerializer",
    "SLIDING_TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainSlidingSerializer",
    "SLIDING_TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSlidingSerializer",
}

"""
dj_rest_auth
""" 
REST_AUTH = {
    'LOGIN_SERIALIZER': 'dj_rest_auth.serializers.LoginSerializer',
    'TOKEN_SERIALIZER': 'dj_rest_auth.serializers.TokenSerializer',
    'JWT_SERIALIZER': 'dj_rest_auth.serializers.JWTSerializer',
    'JWT_SERIALIZER_WITH_EXPIRATION': 'dj_rest_auth.serializers.JWTSerializerWithExpiration',
    'JWT_TOKEN_CLAIMS_SERIALIZER': 'rest_framework_simplejwt.serializers.TokenObtainPairSerializer',
    'USER_DETAILS_SERIALIZER': 'accounts.serializers.NexusUserSerializer',
    'PASSWORD_RESET_SERIALIZER': 'dj_rest_auth.serializers.PasswordResetSerializer',
    'PASSWORD_RESET_CONFIRM_SERIALIZER': 'dj_rest_auth.serializers.PasswordResetConfirmSerializer',
    'PASSWORD_CHANGE_SERIALIZER': 'dj_rest_auth.serializers.PasswordChangeSerializer',

    'REGISTER_SERIALIZER': 'dj_rest_auth.registration.serializers.RegisterSerializer',

    'REGISTER_PERMISSION_CLASSES': ('rest_framework.permissions.AllowAny',),

    'TOKEN_MODEL': 'rest_framework.authtoken.models.Token',
    'TOKEN_CREATOR': 'dj_rest_auth.utils.default_create_token',

    'PASSWORD_RESET_USE_SITES_DOMAIN': False,
    'OLD_PASSWORD_FIELD_ENABLED': False,
    'LOGOUT_ON_PASSWORD_CHANGE': False,
    'SESSION_LOGIN': True,
    'USE_JWT': True,

    'JWT_AUTH_COOKIE': 'access-token',
    'JWT_AUTH_REFRESH_COOKIE': 'refresh-token',
    'JWT_AUTH_REFRESH_COOKIE_PATH': '/',
    'JWT_AUTH_SECURE': False, # the cookie will only be sent through https scheme
    'JWT_AUTH_HTTPONLY': True,
    'JWT_AUTH_SAMESITE': 'Lax',
    'JWT_AUTH_RETURN_EXPIRATION': True,
    'JWT_AUTH_COOKIE_USE_CSRF': False,
    'JWT_AUTH_COOKIE_ENFORCE_CSRF_ON_UNAUTHENTICATED': False,
}



"""
APPLE 
"""
# Apple OAuth (Sign in with Apple)
APPLE_REDIRECT_URI = "https://www.cvan.shop/auth/apple/web-callback/"
APPLE_PUBLIC_KEY_URL = "https://appleid.apple.com/auth/keys"
APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token"
APPLE_CLIENT_ID = os.getenv("APPLE_CLIENT_ID")

APPLE_USERNAME_PREFIX = "APPLE" # user id : {prefix}__{apple_sub}

"""
django-allauth
"""
SITE_ID = 1

# email required, email verification mandatory, authentication method: email, username is not required
ACCOUNT_EMAIL_REQUIRED = True
# ACCOUNT_EMAIL_VERIFICATION = 'mandatory'
# ACCOUNT_AUTHENTICATION_METHOD = 'email'
# ACCOUNT_USERNAME_REQUIRED = False

SOCIALACCOUNT_ADAPTER = 'authApp.customs.common.CustomSocialAccountAdapter'
SOCIALACCOUNT_SOCIALACCOUNT_STR = lambda x: f"{str(getattr(x, 'user', None))}"

# https://github.com/pennersr/django-allauth/blob/main/allauth/socialaccount/adapter.py#L227
# https://github.com/pennersr/django-allauth/blob/main/allauth/socialaccount/models.py#L39
SOCIALACCOUNT_PROVIDERS = {

    # p : 'apple', app_configs : APPS
    "apple": {
        "APPS": [
            # vision os
            {
                "client_id": os.getenv("APPLE_BUNDLE_ID"),
                "secret": os.getenv("APPLE_KEY_ID"),
                "key": os.getenv("APPLE_TEAM_ID"),
                "settings": {
                    # The certificate you downloaded when generating the key.
                    "certificate_key": open("authApp/private/apple_authkey.p8", "r").read(),
                    
                   
                }
            },
            # web service
            {
                "client_id": os.getenv("APPLE_CLIENT_ID"),
                "secret": os.getenv("APPLE_KEY_ID"),
                "key": os.getenv("APPLE_TEAM_ID"),
                "settings": {
                    "certificate_key": open("authApp/private/apple_authkey.p8", "r").read(),
                    "hidden" : True,
                }
            }
        ]
    }
}