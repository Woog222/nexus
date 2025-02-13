# engine/serializers.py
from rest_framework import serializers
from .models import NexusFile

import os

class NexusFileSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField()  # Custom field for owner
    file_name = serializers.SerializerMethodField()

    class Meta:
        model = NexusFile
        fields = ['owner', 'model_file', 'likes', 'views', 'file_name']
        read_only_fields = ['owner', 'model_file']

    def get_owner(self, obj):
        return {'user_name' : obj.owner.user_name, 'user_id' : obj.owner.user_id }

    def get_file_name(self, obj):
        return os.path.basename(obj.model_file.name)


"""
    def to_representation(self, instance):
        # Customize the representation format to "name.file_extension"
        return f"{instance.name}.{instance.file_extension}"
"""