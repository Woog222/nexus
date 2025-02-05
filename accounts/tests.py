from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from rest_framework import status
from rest_framework.test import APIClient

import logging, requests, json

from .views import AppleOauthView

logger = logging.getLogger(__name__)

class NexusUserManagerTests(TestCase):
    """Test custom user manager methods"""

    def setUp(self):
        """Set up test data for the test cases"""
        self.apple_sub = "apple_1234567890"  # A mock Apple sub
        self.email = "testuser@example.com"

    def test_create_user_with_apple_sub(self):
        """Test creating a user with an Apple sub"""

        user = get_user_model().objects.create_user(
            apple_sub=self.apple_sub,
            email=self.email,
        )

        self.assertEqual(user.apple_sub, self.apple_sub)
        self.assertEqual(user.email, self.email)
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_create_user_without_apple_sub(self):
        """Test creating a user without an Apple sub should raise error"""
        with self.assertRaises(ValueError):
            get_user_model().objects.create_user(
                apple_sub=None,
                email=self.email,
            )

    def test_create_superuser(self):
        """Test creating a superuser"""
        user = get_user_model().objects.create_superuser(
            apple_sub=self.apple_sub,
            email=self.email,
        )

        self.assertEqual(user.apple_sub, self.apple_sub)
        self.assertEqual(user.email, self.email)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    def test_create_user_with_unusable_password(self):
        """Test that a user created via Apple OAuth has an unusable password"""
        user = get_user_model().objects.create_user(
            apple_sub=self.apple_sub,
            email=self.email,
        )
        self.assertFalse(user.has_usable_password())  # Should be False due to OAuth


    def test_str_method(self):
        """Test the __str__ method of the NexusUser"""
        user = get_user_model().objects.create_user(
            apple_sub=self.apple_sub,
            email=self.email,
        )
        self.assertEqual(str(user), self.apple_sub)



class AppleOauthViewTestCase(TestCase):
    
    def setUp(self):
        self.client = APIClient()  
        self.url = "/accounts/oauth/apple/callback/"  
    
    def test_callback_view_with_invalid_data(self):
        """Simulate a callback with invalid 'code' value"""

        response = self.client.post(self.url, data={
            'code': 'invalid_auth_code'
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_callback_view_without_data(self):
        """Simulate a callback without the 'code' parameter"""

        response = self.client.post(self.url, data={}, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # {'error' : 'code is missing'}, dict
        self.assertIn('error', response.data)
        self.assertEqual(response.data.get('error'), "code is missing")
