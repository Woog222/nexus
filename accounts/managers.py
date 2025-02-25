# accounts/managers.py
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

import os, logging

from . import utils



logger= logging.getLogger(__name__)

class NexusUserManager(BaseUserManager):
    """Custom user manager that handles user creation via Apple OAuth"""

    def create_user(self, user_id, email=None, password=None, **extra_fields):
        """Create and return a new user with Apple Sign-In"""
        if not user_id:
            raise ValueError("Users must have an user id (apple sub).")

        user = self.model(user_id=user_id, email=self.normalize_email(email), **extra_fields)
        if password:  # Only set a password if provided
            user.set_password(password)
        else:
            user.set_unusable_password()  # Since we use OAuth, no password needed``````````
        user.save(using=self._db)
        return user

    def create_superuser(self, user_id, email=None, password=None, **extra_fields):
        """Create and return a superuser"""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(user_id, email, password, **extra_fields)
