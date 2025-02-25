# accounts/serializers.py
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import NexusUser

import logging

logger = logging.getLogger(__name__)


class NexusUserSerializer(serializers.ModelSerializer):
    liked_files = serializers.SerializerMethodField()

    class Meta:
        model = NexusUser
        fields = [ 'username', 'nickname', 'email', 'date_joined', 'profile_image', 'liked_files']
        read_only_fields = ['username', 'date_joined']  # Prevent updates to `user_id`

    def get_liked_files(self, obj):
        return [{"file_name": str(file), "views": file.views} for file in obj.liked_files.all()]

    def validate(self, attrs):
        """Strict validation: Allow only , `nickname`, `email`, and `profile_image` to be updated."""
        request_method = self.context.get('request').method  # Get HTTP method

        if request_method in ['PUT', 'PATCH']:  # Apply validation to both PUT and PATCH
            allowed_fields = { 'nickname', 'email', 'profile_image'}
            invalid_fields = set(attrs.keys()) - allowed_fields  # Find unexpected fields

            if invalid_fields:
                raise serializers.ValidationError({
                    field: "This field is not allowed for updates."
                    for field in invalid_fields
                })
        return attrs

    def update(self, instance, validated_data):
        """Handle profile image update correctly"""

        logger.info(f"Updating {instance.profile_image.name}")    
        new_image = validated_data.get("profile_image", None)
        if new_image and instance.profile_image and instance.profile_image.name != "user_profile_images/default_profile.jpg":  
            instance.profile_image.delete(save=False)  # Delete old image only if a new one is provided

        
        return super().update(instance, validated_data)




class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        token['email'] = user.email
        # ...

        return token