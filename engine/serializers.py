# engine/serializers.py
from rest_framework import serializers
from .models import NexusFile
from django.urls import reverse
import logging
import os

logger = logging.getLogger(__name__)

class NexusFileSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField()  # Custom field for owner
    file_name = serializers.SerializerMethodField()
    likes = serializers.SerializerMethodField()
    dislikes = serializers.SerializerMethodField()

    class Meta:
        model = NexusFile
        fields = ['owner', 'model_file', 'likes', 'dislikes', 'views', 'file_name']
        read_only_fields = ['owner', 'model_file', 'likes', 'dislikes', 'views', 'file_name']

    def get_owner(self, obj):
        request = self.context.get('request')
        absolute_url = request.build_absolute_uri(reverse('user-detail', kwargs = {'username' : obj.owner.username}))
        return absolute_url

    def get_file_name(self, obj):
        return obj.get_file_name()

    def get_likes(self, obj):
        return obj.liked_users.all().count()

    def get_dislikes(self, obj):
        return obj.disliked_users.all().count()


"""
    def to_representation(self, instance):
        # Customize the representation format to "name.file_extension"
        return f"{instance.name}.{instance.file_extension}"
"""