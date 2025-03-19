# accounts/serializers.py
from django.conf import settings
from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework import (
    serializers,
)
from rest_framework.reverse import reverse as drf_reverse

from .models import NexusUserRelation
import logging

logger = logging.getLogger(__name__)

UserModel = get_user_model()


class NexusUserSerializer(serializers.ModelSerializer):
    following_users = serializers.SerializerMethodField()
    follower_users = serializers.SerializerMethodField()
    blocked_users = serializers.SerializerMethodField()
    reported_users = serializers.SerializerMethodField()
    files_uploaded = serializers.SerializerMethodField()
    liked_files = serializers.SerializerMethodField()

    class Meta:
        model = UserModel
        fields = (
            'nickname',
            'profile_image', 
            # read only fields
            'username', 
            'email', 
            'date_joined', 
            'last_login', 
            'following_users', 
            'follower_users', 
            'blocked_users',
            'reported_users',
            'files_uploaded',
            'liked_files'
        )
        read_only_fields = (
            'username', 
            'email', 
            'date_joined', 
            'last_login', 
            'following_users', 
            'follower_users', 
            'blocked_users', 
            'reported_users',
            'files_uploaded',
            'liked_files'
        )
        extra_kwargs = {
            'nickname': {'required': True},
            # 'profile_image': {'required': True},
        }




    def get_following_users(self, obj):
        request = self.context.get('request')
        absolute_url = request.build_absolute_uri(reverse('user-relation', kwargs={'username': obj.username}))
        query_string = "relation_type=following_users"
        return f"{absolute_url}?{query_string}"
        # return [{"url": relation.to_user.get_absolute_url() } for relation in obj.relations_by_from_user.filter(relation_type=NexusUserRelation.FOLLOW)]

    def get_follower_users(self, obj):
        request = self.context.get('request')
        absolute_url = request.build_absolute_uri(reverse('user-relation', kwargs={'username': obj.username}))
        query_string = "relation_type=follower_users"
        return f"{absolute_url}?{query_string}"
        # return [{"url": relation.from_user.get_absolute_url()} for relation in obj.relations_by_to_user.filter(relation_type=NexusUserRelation.FOLLOW)]

    def get_blocked_users(self, obj):
        request = self.context.get('request')
        absolute_url = request.build_absolute_uri(reverse('user-relation', kwargs={'username': obj.username}))
        query_string = "relation_type=blocked_users"
        return f"{absolute_url}?{query_string}"
        # return [{"url": relation.to_user.get_absolute_url()} for relation in obj.relations_by_from_user.filter(relation_type=NexusUserRelation.BLOCK)]

    def get_reported_users(self, obj):
        request = self.context.get('request')
        absolute_url = request.build_absolute_uri(reverse('user-relation', kwargs={'username': obj.username}))
        query_string = "relation_type=reported_users"
        return f"{absolute_url}?{query_string}"
        # return [{"url": relation.to_user.get_absolute_url()} for relation in obj.relations_by_from_user.filter(relation_type=NexusUserRelation.REPORT)]

    def get_files_uploaded(self, obj):
        request = self.context.get('request')
        absolute_url = request.build_absolute_uri(reverse('nexusfile-list-create'))
        query_string = f"owner={obj.username}"
        return f"{absolute_url}?{query_string}"

    def get_liked_files(self, obj):
        request = self.context.get('request')
        absolute_url = request.build_absolute_uri(reverse('nexusfile-list-create'))
        query_string = f"liked_user={obj.username}"
        return f"{absolute_url}?{query_string}"


    @staticmethod
    def validate_username(username):
        if 'allauth.account' not in settings.INSTALLED_APPS:
            # We don't need to call the all-auth
            # username validator unless its installed
            return username

        from allauth.account.adapter import get_adapter
        username = get_adapter().clean_username(username)
        return username

    @staticmethod
    def validate_email(email):
        if 'allauth.account' not in settings.INSTALLED_APPS:
            return email
        from allauth.account.adapter import get_adapter
        email = get_adapter().clean_email(email)
        return email

    def validate(self, attrs):
        """Strict validation: Allow only , `nickname`, `email`, and `profile_image` to be updated."""
            # request_method = self.context.get('request').method  # Get HTTP method

            # if request_method in ['PUT', 'PATCH']:  # Apply validation to both PUT and PATCH
            #     allowed_fields = { 'nickname', 'email', 'profile_image'}
            #     invalid_fields = set(attrs.keys()) - allowed_fields  # Find unexpected fields

            #     if invalid_fields:
            #         raise serializers.ValidationError({
            #             field: "This field is not allowed for updates."
            #             for field in invalid_fields
            #         })
        return attrs

    def update(self, instance, validated_data):
        """Handle profile image update correctly"""

        
        new_image = validated_data.get("profile_image", None)
        if new_image and instance.profile_image and instance.profile_image.name != "user_profile_images/default_profile.jpg":  
            instance.profile_image.delete(save=False)  # Delete old image only if a new one is provided

        ret = super().update(instance, validated_data)
        logger.info(f"[user update({instance.username})] {validated_data} updated")    
        return ret




