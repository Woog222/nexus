from dotenv import load_dotenv
import os


load_dotenv()

"""
JWT
"""
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')  # Default for safety
JWT_ACCESS_MIN = int(os.getenv('JWT_ACCESS_MIN', 30))  # Ensure it's int
JWT_REFRESH_DAY = int(os.getenv('JWT_REFRESH_DAY', 30))  # Ensure it's int


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