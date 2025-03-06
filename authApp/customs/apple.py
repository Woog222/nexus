from allauth.socialaccount.providers.apple.client import AppleOAuth2Client
from allauth.socialaccount.providers.apple.views import AppleOAuth2Adapter
from dj_rest_auth.registration.serializers import SocialLoginSerializer
import logging

logger = logging.getLogger(__name__)


class CustomAppleLoginSerializer(SocialLoginSerializer):
    def validate(self, attrs):
        attrs = super().validate(attrs)
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
        return social_login


class CustomAppleOAuth2Adapter(AppleOAuth2Adapter):
    def parse_token(self, data):
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
    