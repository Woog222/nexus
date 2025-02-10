from rest_framework import serializers
from .models import NexusUser

class NexusUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = NexusUser
        fields = ['user_id', 'user_name', 'email']
