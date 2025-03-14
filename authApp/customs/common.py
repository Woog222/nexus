from allauth.socialaccount.adapter import DefaultSocialAccountAdapter

import logging

logger = logging.getLogger(__name__)



class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        return user

    def save_user(self, request, sociallogin, form=None):


        u = sociallogin.user
        logger.debug(f"[save_user] sociallogin.user(before) : {u}")

        ret = super().save_user(request, social_login, form)
        

        logger.debug(f"[save_user] sociallogin.user(after) : {ret}")

        return ret