from django.test import TestCase
from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.exceptions import ValidationError
from rest_framework import status
from rest_framework.test import APIClient

import logging, requests, json, jwt, datetime

from accounts.utils import (
    create_access_token,
    create_refresh_token,
    refresh_access_token,
    validate_access_token
)
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


class JWTTokenUtilsTest(TestCase):
    def setUp(self):
        self.user_id = "test-user-123"
        self.email = "test@example.com"
        self.secret_key = settings.JWT_SECRET_KEY  
        self.access_token = create_access_token(self.user_id, self.email)
        self.refresh_token = create_refresh_token(self.user_id)

    def test_create_access_token(self):
        decoded = validate_access_token(self.access_token)
        self.assertEqual(decoded["sub"], self.user_id)
        self.assertEqual(decoded["email"], self.email)
        self.assertEqual(decoded["iss"], "nexus")

    def test_create_refresh_token(self):
        decoded = jwt.decode(self.refresh_token, self.secret_key, algorithms=["HS256"])
        self.assertEqual(decoded["sub"], self.user_id)
        self.assertEqual(decoded["iss"], "nexus")

    def test_refresh_access_token(self):
        new_access_token = refresh_access_token(self.refresh_token)
        decoded = validate_access_token(new_access_token)
        self.assertEqual(decoded["sub"], self.user_id)
        self.assertEqual(decoded["email"], self.email)
        self.assertEqual(decoded["iss"], "nexus")

    def test_expired_access_token(self):
        expired_payload = {
            "sub": self.user_id,
            "email": self.email,
            "exp": datetime.datetime.utcnow() - datetime.timedelta(seconds=1),
            "iat": datetime.datetime.utcnow(),
            "iss": "nexus"
        }
        expired_token = jwt.encode(expired_payload, self.secret_key, algorithm="HS256")

        with self.assertRaises(jwt.ExpiredSignatureError):
            validate_access_token(expired_token)

    def test_invalid_access_token(self):
        invalid_token = "invalid.token.string"

        with self.assertRaises(jwt.InvalidTokenError):
            validate_access_token(invalid_token)

    def test_tampered_access_token(self):
        tampered_access_token = self.access_token[:-1] + "X"  # Change last character to 'X'

        with self.assertRaises(jwt.InvalidTokenError):
            validate_access_token(tampered_access_token)

    def test_tampered_refresh_token(self):
        tampered_refresh_token = self.refresh_token[:-1] + "X"  # Change last character to 'X'

        with self.assertRaises(jwt.InvalidTokenError):
            jwt.decode(tampered_refresh_token, self.secret_key, algorithms=["HS256"])

    def test_tampered_token_with_wrong_signature(self):
        # Create a new token and tamper with the signature
        valid_token = create_access_token(self.user_id, self.email)
        parts = valid_token.split(".")
        tampered_token = parts[0] + "." + parts[1] + "." + "tampered_signature"

        with self.assertRaises(jwt.InvalidTokenError):
            validate_access_token(tampered_token)