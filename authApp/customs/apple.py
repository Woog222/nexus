from allauth.socialaccount.providers.apple.client import AppleOAuth2Client
from allauth.socialaccount.providers.apple.views import AppleOAuth2Adapter
from allauth.socialaccount.adapter import get_adapter as get_social_account_adapter
from dj_rest_auth.registration.serializers import SocialLoginSerializer

from django.conf import settings



import logging

logger = logging.getLogger(__name__)


class CustomAppleLoginSerializer(SocialLoginSerializer):
    def validate(self, attrs):
        logger.debug(attrs)

        ###################### CUSTOM CODE ######################

        # view = self.context.get('view')
        # request = self._get_request()
        # adapter_class = getattr(view, 'adapter_class', None)
        # adapter = adapter_class(request)
        # app = adapter.get_app(request)

        # code = attrs.get("code")
        # if not code:
        #     logger.debug("code is not found")
        
        #     self.set_callback_url(view=view, adapter_class=adapter_class)
        #     self.client_class = getattr(view, 'client_class', None)

        # if not self.client_class:
        #     raise serializers.ValidationError(
        #         _('Define client_class in view'),
        #     )

        # provider = adapter.get_provider()
        # scope = provider.get_scope_from_request(request)
        # client = self.client_class(
        #     request,
        #     app.client_id,
        #     app.secret,
        #     adapter.access_token_method,
        #     adapter.access_token_url,
        #     self.callback_url,
        #     scope,
        #     scope_delimiter=adapter.scope_delimiter,
        #     headers=adapter.headers,
        #     basic_auth=adapter.basic_auth,
        # )
        # token = client.get_access_token(code)
        # logger.debug(token)

        ##########################################################
        
        attrs = super().validate(attrs)
        logger.debug(attrs)
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
        logger.debug(f"token: {token.user_data.keys()}")
        logger.debug(f"sub: {sub}")
        logger.debug(f"email: {email}")
        logger.debug(f"social_login.state: {getattr(social_login, 'state')}")

        logger.debug(f"social_login.user: {social_login.user}")
        logger.debug(f"social_login.is_existing: {social_login.is_existing}")
        if sub:
            socialaccount_adapter.populate_user(
                request = self._get_request(),
                sociallogin = social_login,
                data = {
                    "username": f"{settings.APPLE_USERNAME_PREFIX}__{sub}",
                    "email" : email,
                }
            )
        logger.debug(f"social_login.is_existing: {social_login.is_existing}")    
        logger.debug(f"social_login.user: {social_login.user}")
        logger.debug(f"social_login.is_headless: {social_login.is_headless}")
        logger.debug(f"social_login.state.process  :{social_login.state.get("process")}")
        return social_login


class CustomAppleOAuth2Adapter(AppleOAuth2Adapter):
    def parse_token(self, data):
        logger.debug(data)
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
    