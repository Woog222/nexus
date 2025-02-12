# accounts/serializers.py
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import NexusUser

import logging

logger = logging.getLogger(__name__)

class NexusUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = NexusUser
        fields = ['user_id', 'user_name', 'email', 'profile_image']
        read_only_fields = ['user_id']  # Prevent updates to `user_id`

    def validate(self, attrs):
        """Strict validation: Allow only `user_name`, `email`, and `profile_image` to be updated."""
        request_method = self.context.get('request').method  # Get HTTP method

        if request_method in ['PUT', 'PATCH']:  # Apply validation to both PUT and PATCH
            allowed_fields = {'user_name', 'email', 'profile_image'}
            invalid_fields = set(attrs.keys()) - allowed_fields  # Find unexpected fields

            if invalid_fields:
                raise serializers.ValidationError({
                    field: "This field is not allowed for updates."
                    for field in invalid_fields
                })
        return attrs

    def update(self, instance, validated_data):
        """Handle profile image update correctly"""

        
        new_image = validated_data.get("profile_image", None)
        
        logger.debug(f"{new_image} -> {instance.profile_image.name}")

        if new_image and instance.profile_image and instance.profile_image.name != "user_profile_images/default_profile.jpg":  
            logger.debug(f"{instance.profile_image.name} deleted")
            instance.profile_image.delete(save=False)  # Delete old image only if a new one is provided
            
        
        return super().update(instance, validated_data)




class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['user_id'] = user.user_id
        token['email'] = user.email
        # ...

        return token