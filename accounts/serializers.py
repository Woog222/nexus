# accounts/serializers.py
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import NexusUser

class NexusUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = NexusUser
        fields = ['user_id', 'user_name', 'email']
        read_only_fields = ['user_id']  # Prevent updates to `user_id`

    def validate(self, attrs):
        """Strict validation: Allow only `user_name` and `email` to be updated."""
        request_method = self.context.get('request').method  # Get HTTP method

        # Only enforce field restrictions for PATCH/PUT (updates)
        if request_method in ['PATCH', 'PUT']:
            allowed_fields = {'user_name', 'email'}
            invalid_fields = set(attrs.keys()) - allowed_fields  # Find unexpected fields

            if invalid_fields:
                raise serializers.ValidationError({
                    field: "This field is not allowed for updates."
                    for field in invalid_fields
                })



        return attrs


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['user_id'] = user.user_id
        token['email'] = user.email
        # ...

        return token