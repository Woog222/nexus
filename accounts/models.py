from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

class NexusUserManager(BaseUserManager):
    """Custom user manager that handles user creation via Apple OAuth"""

    def create_user(self, apple_sub, email=None, **extra_fields):
        """Create and return a new user with Apple Sign-In"""
        if not apple_sub:
            raise ValueError("Users must have an Apple sub (unique ID)")

        user = self.model(apple_sub=apple_sub, email=self.normalize_email(email), **extra_fields)
        user.set_unusable_password()  # Since we use OAuth, no password needed
        user.save(using=self._db)
        return user

    def create_superuser(self, apple_sub, email=None, **extra_fields):
        """Create and return a superuser"""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(apple_sub, email, **extra_fields)

class NexusUser(AbstractBaseUser, PermissionsMixin):
    """Custom user model using Apple OAuth instead of username/password"""

    apple_sub = models.CharField(max_length=255, unique=True)  # Unique Apple user ID
    email = models.EmailField(null=True, blank=True)
    access_token = models.TextField(null=True, blank=True)  # todo
    refresh_token = models.TextField(null=True, blank=True)  # todo
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # Required for Django admin

    objects = NexusUserManager()

    USERNAME_FIELD = "apple_sub"  # Unique identifier (instead of username)
    REQUIRED_FIELDS = ["email"]  # Required when creating superuser

    def __str__(self):
        return self.apple_sub
