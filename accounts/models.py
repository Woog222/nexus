# accounts/models.py
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

import os, logging

from . import utils


logger= logging.getLogger(__name__)

class NexusUserManager(BaseUserManager):
    """Custom user manager that handles user creation via Apple OAuth"""

    def create_user(self, user_id, email=None, **extra_fields):
        """Create and return a new user with Apple Sign-In"""
        if not user_id:
            raise ValueError("Users must have an user id (apple sub).")

        user = self.model(user_id=user_id, email=self.normalize_email(email), **extra_fields)
        user.set_unusable_password()  # Since we use OAuth, no password needed
        user.save(using=self._db)
        return user

    def create_superuser(self, user_id, email=None, **extra_fields):
        """Create and return a superuser"""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(user_id, email, **extra_fields)

class NexusUser(AbstractBaseUser, PermissionsMixin):
    """Custom user model using Apple OAuth instead of username/password"""

    user_id = models.CharField(max_length=255, unique=True)  # sub from Apple
    user_name = models.CharField(max_length=255, null=False, blank=False, default="Anonymous_user")
    email = models.EmailField(null=False, blank=False)
    profile_image = models.ImageField(
        upload_to= utils.get_NexusUser_profile_image_upload_path,
        default="user_profile_images/default_profile.jpg",
        null = False,
        blank = False,
        max_length = 300,
    )


    apple_access_token = models.TextField(null=True, blank=True)  # todo
    apple_refresh_token = models.TextField(null=True, blank=True)  # todo

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # Required for Django admin
    objects = NexusUserManager()

    USERNAME_FIELD = "user_id"  # Unique identifier (instead of username)
    REQUIRED_FIELDS = ["email"]  # Required when creating superuser

    def __str__(self):
        return f"{self.user_id}"


    def delete(self, *args, **kwargs):
        # Override the delete method to remove the profile image before deleting the instance
        if self.profile_image:
            file_path = self.profile_image.path
            if self.profile_image.name != 'user_profile_images/default_profile.jpg' and  os.path.isfile(file_path):
                os.remove(file_path)  # Delete the actual file

        logger.info(f"{self.user_name}  ({self.user_id}) is deleted.")
        super(NexusUser, self).delete(*args, **kwargs)
        
