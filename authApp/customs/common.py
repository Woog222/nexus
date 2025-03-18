from allauth.socialaccount.adapter import DefaultSocialAccountAdapter

import logging

logger = logging.getLogger(__name__)



class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        return user

    def save_user(self, request, sociallogin, form=None):


        u = sociallogin.user
        

        ret = super().save_user(request, sociallogin, form)
        logger.info(f"[Signup (DefaultSocialAccountAdapter.save_user)] created user:\n{u}")

        return ret