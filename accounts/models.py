# accounts/models.py
from django.db import models
from django.contrib.auth.models import AbstractBaseUser,PermissionsMixin
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.urls import reverse

from rest_framework import pagination

import os, logging

from . import utils
from .managers import NexusUserManager



logger= logging.getLogger(__name__)



class NexusUser(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model using Apple OAuth instead of username/password
    """

    username = models.CharField(max_length=255, null=False, blank=False, unique=True) 
    nickname = models.CharField(max_length=255, null=False, blank=False, default="Anonymous") # nickname
    email = models.EmailField(null=False, blank=False, unique=True) # unique email
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True, blank=True, null=True)

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



    relations = models.ManyToManyField( 
        'self', 
        symmetrical=False, 
        through='NexusUserRelation',  # Use string reference to avoid definition ordering issue
        related_name='+', # not to create a backwards relation
    ) # Follow OR Block
    
    objects = NexusUserManager() # custom manager

    USERNAME_FIELD = "username"  # Unique identifier (practically a primary key)
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = ["email", "nickname"]  # Required when creating superuser

    class Meta:
        ordering = ['-date_joined']

    def get_absolute_url(self):
        return reverse('user-detail', kwargs={'username': self.username})
    
    def verbose_name(self):
        return f"{self.username} ({self.nickname}) ({self.id}) ({self.email})"
    
    def get_full_name(self):
        return f"{self.username} ({self.id})"
    
    def get_short_name(self):
        return self.username

    
    def __str__(self):
        return self.verbose_name()


@receiver(post_delete, sender=NexusUser)
def deleteNexusUser(sender, instance, **kwargs):
    """Ensure profile image deleteion when NexusFile is deleted."""
    if instance.profile_image:
        file_path = instance.profile_image.path
        if instance.profile_image.name != 'user_profile_images/default_profile.jpg' and  os.path.isfile(file_path):
            os.remove(file_path)  # Delete the actual file

    logger.info(f"{str(instance)} is deleted.")

class NexusUserRelation(models.Model):
    """
    Intermediary User relation model for follow OR block
    """
    
    FOLLOW = 'F'
    BLOCK = 'B'
    REPORT = 'R'
    RELATION_CHOICES = [
        (FOLLOW, 'follow'),
        (BLOCK, 'block'),
        (REPORT, 'report'),
    ]

    from_user = models.ForeignKey(NexusUser, on_delete=models.CASCADE, related_name='relations_by_from_user')
    to_user = models.ForeignKey(NexusUser, on_delete=models.CASCADE, related_name='relations_by_to_user')
    relation_type = models.CharField(max_length=10, choices=RELATION_CHOICES)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['from_user', 'to_user', 'relation_type'], name='unique_relation')
        ]

    def __str__(self):
        return f"{self.from_user} {self.get_relation_type_display()}s {self.to_user}"

class NexusUserRelationPagination(pagination.PageNumberPagination):
    page_size = 10  # Default number of items per page
    page_size_query_param = 'page_size'  # Allows clients to set a custom page size
    max_page_size = 100  # Maximum items per pages