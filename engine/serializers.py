# engine/serializers.py
from rest_framework import serializers
from .models import NexusFile

import os

class NexusFileSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField()  # Custom field for owner
    file_name = serializers.SerializerMethodField()
    likes= serializers.SerializerMethodField()

    class Meta:
        model = NexusFile
        fields = ['owner', 'model_file', 'likes', 'views', 'file_name']
        read_only_fields = ['owner', 'model_file']

    def get_owner(self, obj):
        return {'username' : obj.owner.username, 'nickname' : obj.owner.nickname }

    def get_file_name(self, obj):
        return os.path.basename(obj.model_file.name)

    def get_likes(self, obj):
        return obj.like_users.all().count()


"""
    def to_representation(self, instance):
        # Customize the representation format to "name.file_extension"
        return f"{instance.name}.{instance.file_extension}"
"""