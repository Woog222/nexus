from allauth.socialaccount.providers.apple.client import AppleOAuth2Client
from allauth.socialaccount.providers.apple.views import AppleOAuth2Adapter
from allauth.socialaccount.adapter import get_adapter as get_social_account_adapter
from dj_rest_auth.registration.serializers import SocialLoginSerializer

from django.conf import settings



import logging

logger = logging.getLogger(__name__)


class CustomAppleLoginSerializer(SocialLoginSerializer):
    def validate(self, attrs):
        attrs = super().validate(attrs)
        logger.info(f"[user login] {attrs.get('user')}")
        return attrs

    def get_social_login(self, adapter, app, token, response):
        """
        :param adapter: allauth.socialaccount Adapter subclass.
            Usually OAuthAdapter or Auth2Adapter
        :param app: `allauth.socialaccount.SocialApp` instance
        :param token: `allauth.socialaccount.SocialToken` instance
        :param response: Provider's response for OAuth1. Not used in the
        :returns: A populated instance of the
            `allauth.socialaccount.SocialLoginView` instance
        """
        social_login = super().get_social_login(adapter, app, token, response)
        socialaccount_adapter = get_social_account_adapter()

        sub = getattr(token, "user_data").get("sub")
        email = getattr(token, "user_data").get("email")
        info_dict = {
            'sub' : sub,
            'email' : email,
            'token_keys' : token.user_data.keys(),
            'social_login' : social_login,
            'social_login.user' : social_login.user,
            'social_login.is_existing' : social_login.is_existing,
            'social_login.is_headless' : social_login.is_headless,
            'social_login.state.process' : social_login.state.get("process"),
        }

        logger.info(f"[get_social_login] \n{info_dict}")
        if sub:
            socialaccount_adapter.populate_user(
                request = self._get_request(),
                sociallogin = social_login,
                data = {
                    "username": f"{settings.APPLE_USERNAME_PREFIX}__{sub}",
                    "email" : email,
                }
            )
        logger.info(f"[get_social_login] social_login.user(after populate_user): {social_login.user}")    
        return social_login


class CustomAppleOAuth2Adapter(AppleOAuth2Adapter):
    def parse_token(self, data):
        logger.debug(f"[parse_token] data: {data}")
        token = super().parse_token(data)  # Calls parent class's method
        return token

class CustomAppleOAuth2Client(AppleOAuth2Client):

    def get_access_token(self, *args, **kwargs):
        token = super().get_access_token(*args, **kwargs)
        return token
    def __init__(
        self,
        request,
        consumer_key,
        consumer_secret,
        access_token_method,
        access_token_url,
        callback_url,
        _scope,  # This is fix for incompatibility between django-allauth==65.3.1 and dj-rest-auth==7.0.1
        scope_delimiter=" ",
        headers=None,
        basic_auth=False,
    ):
        super().__init__(
            request,
            consumer_key,
            consumer_secret,
            access_token_method,
            access_token_url,
            callback_url,
            scope_delimiter,
            headers,
            basic_auth,
        )
    