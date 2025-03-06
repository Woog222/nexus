from allauth.socialaccount.adapter import DefaultSocialAccountAdapter

import logging

logger = logging.getLogger(__name__)



class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):

    def populate_user(self, request, sociallogin, data):
        logger.debug(f"data: {data}")
        user = super().populate_user(request, sociallogin, data)
        logger.debug(f"user: {user}")
        return user
