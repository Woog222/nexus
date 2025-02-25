# accounts/models.py
from django.db import models
from django.contrib.auth.models import AbstractBaseUser,PermissionsMixin
from django.db.models.signals import post_delete
from django.dispatch import receiver

import os, logging

from . import utils
from .managers import NexusUserManager


logger= logging.getLogger(__name__)



class NexusUser(AbstractBaseUser, PermissionsMixin):
    """Custom user model using Apple OAuth instead of username/password"""

    username = models.CharField(max_length=255, null=False, blank=False, unique=True) # nickname
    nickname = models.CharField(max_length=255, null=False, blank=False, default="Anonymous") # unique email
    email = models.EmailField(null=False, blank=False, unique=True) # unique email
    date_joined = models.DateTimeField(auto_now_add=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    profile_image = models.ImageField(
        upload_to= utils.get_NexusUser_profile_image_upload_path,
        default="user_profile_images/default_profile.jpg",
        null = False,
        blank = False,
        max_length = 300,
    )

    liked_files = models.ManyToManyField('engine.NexusFile', related_name='like_users')
    objects = NexusUserManager()



    USERNAME_FIELD = "username"  # Unique identifier (instead of username)
    REQUIRED_FIELDS = ["email", "nickname"]  # Required when creating superuser


    def get_full_name(self):
        return f"{self.username} ({self.id})"
    
    def get_short_name(self):
        return self.username
    
    def __str__(self):
        return self.get_full_name()


@receiver(post_delete, sender=NexusUser)
def deleteNexusUser(sender, instance, **kwargs):
    """Ensure profile image deleteionwhen NexusFile is deleted."""
    if instance.profile_image:
        file_path = instance.profile_image.path
        if instance.profile_image.name != 'user_profile_images/default_profile.jpg' and  os.path.isfile(file_path):
            os.remove(file_path)  # Delete the actual file

    logger.info(f"{str(instance)} is deleted.")
