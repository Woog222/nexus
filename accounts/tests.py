# accounts/tests.py
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import path, reverse
from django.utils import timezone
from rest_framework.response import Response
from rest_framework import (
    status, 
    decorators,
    permissions,
    test,
)
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

import logging, requests, json, jwt, datetime, copy, os

from .views import AppleOauthView
from .models import NexusUser
from .serializers import NexusUserSerializer
from .factories import NexusUserFactory

logger = logging.getLogger(__name__)


class NexusUserManagerTests(test.APITestCase):
    """Test custom user manager methods"""

    def setUp(self):
        """Set up test data for the test cases"""
        self.user_id = "apple_1234567890"  # A mock Apple sub
        self.email = "testuser@example.com"
        self.user_name = "Test User"  # New user name for tests
        self.default_user_name = "Anonymous_user"

    def test_create_user_with_default_user_name(self):
        """Test that the default user_name is used when not provided"""

        user = get_user_model().objects.create_user(
            user_id=self.user_id,
            email=self.email,
            # Notice that we are not passing user_name here
        )

        # Check that the user_name is set to the default value
        self.assertEqual(user.user_name, self.default_user_name)
        self.assertEqual(user.user_id, self.user_id)
        self.assertEqual(user.email, self.email)

    def test_create_user_with_user_id(self):
        """Test creating a user with an Apple sub"""

        user = get_user_model().objects.create_user(
            user_id=self.user_id,
            email=self.email,
            user_name=self.user_name 
        )

        self.assertEqual(user.user_id, self.user_id)
        self.assertEqual(user.email, self.email)
        self.assertEqual(user.user_name, self.user_name)  #
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertIsNone(user.apple_access_token)
        self.assertIsNone(user.apple_refresh_token)

        user.delete()
        # without username
        user = get_user_model().objects.create_user(
            user_id=self.user_id,
            email=self.email,
        )
        self.assertEqual(user.user_id, self.user_id)
        self.assertEqual(user.email, self.email)
        self.assertEqual(user.user_name, self.default_user_name)  
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertIsNone(user.apple_access_token)
        self.assertIsNone(user.apple_refresh_token)
        

    def test_create_user_without_user_id(self):
        """Test creating a user without an Apple sub should raise error"""
        with self.assertRaises(ValueError):
            get_user_model().objects.create_user(
                user_id=None,
                email=self.email,
                user_name=self.user_name  
            )

        # without username
        with self.assertRaises(ValueError):
            get_user_model().objects.create_user(
                user_id=None,
                email=self.email,
            )

    def test_create_superuser(self):
        """Test creating a superuser"""
        user = get_user_model().objects.create_superuser(
            user_id=self.user_id,
            email=self.email,
            user_name=self.user_name  
        )

        self.assertEqual(user.user_id, self.user_id)
        self.assertEqual(user.email, self.email)
        self.assertEqual(user.user_name, self.user_name)  
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertIsNone(user.apple_access_token)
        self.assertIsNone(user.apple_refresh_token)
        user.delete()
        
        # without username
        user = get_user_model().objects.create_superuser(
            user_id=self.user_id,
            email=self.email,
        )

        self.assertEqual(user.user_id, self.user_id)
        self.assertEqual(user.email, self.email)
        self.assertEqual(user.user_name, self.default_user_name)  
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertIsNone(user.apple_access_token)
        self.assertIsNone(user.apple_refresh_token)

    def test_create_user_with_unusable_password(self):
        """Test that a user created via Apple OAuth has an unusable password"""
        user = get_user_model().objects.create_user(
            user_id=self.user_id,
            email=self.email,
            user_name=self.user_name  # user_name included
        )
        self.assertFalse(user.has_usable_password())  # Should be False due to OAuth

    def test_str_method(self):
        """Test the __str__ method of the NexusUser"""
        user = get_user_model().objects.create_user(
            user_id=self.user_id,
            email=self.email,
            user_name=self.user_name  # Pass the user_name here
        )
        self.assertEqual(str(user), self.user_id)  # Ensure the string representation is based on user_id

    def test_user_update_tokens(self):
        """Test updating the user tokens"""
        user = get_user_model().objects.create_user(
            user_id=self.user_id,
            email=self.email,
            user_name=self.user_name  # user_name included
        )

        # Update the tokens
        user.apple_access_token = "new_apple_access_token"
        user.apple_refresh_token = "new_apple_refresh_token"
        user.save()
        user.refresh_from_db() 
        self.assertEqual(user.apple_access_token, "new_apple_access_token")
        self.assertEqual(user.apple_refresh_token, "new_apple_refresh_token")
        self.assertEqual(user.user_name, self.user_name)  

class NexusUserProfileImageTests(test.APITestCase):
    """Test user creation and profile updates"""

    def setUp(self):
        """Setup test user and authentication"""
        self.user = NexusUserFactory()
        self.token = str(AccessToken.for_user(self.user))
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.update_url = reverse('user-update')

    def tearDown(self):
        # Check if the user exists in the database and delete it
        if self.user and NexusUser.objects.filter(id=self.user.id).exists():
            self.user.delete()

    def test_user_creation(self):
        """Test creating a user via factory"""
        self.assertEqual(NexusUser.objects.count(), 1)

    def test_update_username_and_email(self):
        """Test updating user_name and email (JSON request)"""
        payload = {
            "user_name": "Updated User",
            "email": "updated@example.com"
        }
        response = self.client.patch(self.update_url, payload, format="json")

        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.user_name, "Updated User")
        self.assertEqual(self.user.email, "updated@example.com")

    def test_update_invalid_profile_image(self):
        """Test updating profile image (multipart/form-data)"""
        invalid_image_binary = b"invalid_image_binary"

        temp_file = SimpleUploadedFile("new_profile.jpg", invalid_image_binary, content_type="image/jpeg")
        response = self.client.patch(self.update_url, {"profile_image": temp_file}, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # {'profile_image': [ErrorDetail(string='Upload a valid image. The file you uploaded was either not an image or a corrupted image.', code='invalid_image')]}


    def get_valid_image_bianry_content(self):
        from io import BytesIO
        from PIL import Image
        # Create a simple valid image using PIL (e.g., a 100x100 red image)
        img = Image.new('RGB', (100, 100), color='red')
        img_byte_arr = BytesIO()
        img.save(img_byte_arr, format='JPEG')

        return img_byte_arr.getvalue()

    def test_update_vaild_profile_image(self):

        valid_image_bianry = self.get_valid_image_bianry_content()
        temp_file = SimpleUploadedFile("new_profile.jpg", valid_image_bianry, content_type="image/jpeg")
        response = self.client.patch(self.update_url, {"profile_image": temp_file}, format="multipart")

        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(self.user.profile_image.name.startswith("user_profile_images/"))

        # Compares the contents
        with open(self.user.profile_image.path, 'rb') as f:
            file_content = f.read()
        self.assertEqual(valid_image_bianry, file_content)

    def test_profile_image_deletion_on_update(self):
        """Test that the old profile image is deleted when a new one is uploaded"""
        old_image_path = self.user.profile_image.path  # Save old image path

        valid_image_bianry = self.get_valid_image_bianry_content()
        temp_file = SimpleUploadedFile("updated_profile.jpg", valid_image_bianry, content_type="image/jpeg")
        response = self.client.patch(self.update_url, {"profile_image": temp_file}, format="multipart")

        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Ensure old file is removed
        self.assertFalse(os.path.exists(old_image_path), "Old profile image was not deleted")

    def test_profile_image_deletion_on_instance_deletion(self):
        """Test that the old profile image is deleted when the instance is deleted."""
        old_image_path = self.user.profile_image.path  # Save old image path
        self.user.delete()
        logger.debug(old_image_path)

        # Ensure old file is removed
        self.assertFalse(os.path.exists(old_image_path), "Old profile image was not deleted")


    def test_update_with_invalid_field(self):
        """Test updating with an invalid field"""
        payload = {"invalid_field": "not allowed"}

        # patch (ignored)
        response = self.client.patch(self.update_url, payload, format="json")
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.user_id, response.json().get('user_id'))
        self.assertEqual(self.user.user_name, response.json().get('user_name'))
        self.assertEqual(self.user.email, response.json().get('email'))

        # put (invalid)
        response = self.client.put(self.update_url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_unauthorized_access(self):
        """Test that an unauthorized user cannot update the profile"""
        self.client.credentials()  # Remove authentication
        response = self.client.patch(self.update_url, {"user_name": "Unauthorized User"}, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class NexusUserAPITestCase(test.APITestCase):
    """ Test User API """

    def setUp(self):
        self.user_id = 'test_user_123'
        self.email = 'test@example.com'
        self.user_name = 'test_user_name'

        self.user = get_user_model().objects.create(user_id=self.user_id, email=self.email)
        refresh = RefreshToken.for_user(self.user)

        self.user_detail_url = reverse('user-detail')
        self.user_update_url = reverse('user-update')
        self.refresh_access_token_url = reverse('token-refresh')

        self.token_creation_timestamp = timezone.now().timestamp()
        self.access_token = str(refresh.access_token)
        self.refresh_token = str(refresh)

    def test_token_basic(self):
        decoded_access = jwt.decode(self.access_token, settings.SIMPLE_JWT["SIGNING_KEY"], algorithms=["HS256"])
        decoded_refresh = jwt.decode(self.refresh_token, settings.SIMPLE_JWT["SIGNING_KEY"], algorithms=["HS256"])
        # Validate Token creation Time (iat)
        self.assertAlmostEqual(decoded_access["iat"], self.token_creation_timestamp, delta=5)  # Allow 5 sec margin
        self.assertAlmostEqual(decoded_refresh["iat"], self.token_creation_timestamp, delta=5)  # Allow 5 sec margin

        # Validate Access Token Expiration
        expected_access_exp = self.token_creation_timestamp + settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()
        self.assertAlmostEqual(decoded_access["exp"], expected_access_exp, delta=5)  # Allow 5 sec margin

        # Validate Refresh Token Expiration
        expected_refresh_exp = self.token_creation_timestamp + settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()
        self.assertAlmostEqual(decoded_refresh["exp"], expected_refresh_exp, delta=5)  # Allow 5 sec margin

    def test_refresh_access_token(self):
        response = self.client.post(
            path = self.refresh_access_token_url,
            data= {"refresh" : self.refresh_token}
        )
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

        # Decode the tokens
        access_token = response.data["access"]
        refresh_token = response.data["refresh"]

        decoded_access = jwt.decode(access_token, settings.SIMPLE_JWT["SIGNING_KEY"], algorithms=["HS256"])
        decoded_refresh = jwt.decode(refresh_token, settings.SIMPLE_JWT["SIGNING_KEY"], algorithms=["HS256"])

        self.assertEqual(decoded_access['token_type'], 'access')
        self.assertEqual(decoded_refresh['token_type'], 'refresh')
        self.assertEqual(decoded_access['user_id'], self.user_id)
        self.assertEqual(decoded_refresh['user_id'], self.user_id)

        # Get current timestamp (in UTC)
        now_timestamp = timezone.now().timestamp()

        # Validate Token creation Time (iat)
        self.assertAlmostEqual(decoded_access["iat"], now_timestamp, delta=5)  # Allow 5 sec margin
        self.assertAlmostEqual(decoded_refresh["iat"], now_timestamp, delta=5)  # Allow 5 sec margin

        # Validate Access Token Expiration
        expected_access_exp = now_timestamp + settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()
        self.assertAlmostEqual(decoded_access["exp"], expected_access_exp, delta=5)  # Allow 5 sec margin

        # Validate Refresh Token Expiration
        expected_refresh_exp = now_timestamp + settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()
        self.assertAlmostEqual(decoded_refresh["exp"], expected_refresh_exp, delta=5)  # Allow 5 sec margin

        
    def test_get_user_detail_success(self):
        response = self.client.get(
            path=self.user_detail_url, 
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}"  # Send the token in header
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK) 

        expected_data = NexusUserSerializer(self.user).data
        for key in expected_data.keys():
            self.assertIn(key , response.json())


    def test_missing_access_token(self):
        response = self.client.get(path=self.user_detail_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_invalid_access_token(self):
        response = self.client.get(
            path = self.user_detail_url, 
            HTTP_AUTHORIZATION='Bearer invalid_token'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)



    def test_access_token_of_non_existing_user(self):
        self.user = get_user_model().objects.create_user(
            user_id="test_user_id",
            email="test_email@gmail.com",
            user_name= "test_user_name" 
        )
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)

        # valid yet
        response = self.client.get(
            path = self.user_detail_url, 
            HTTP_AUTHORIZATION=f"Bearer {access_token}"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user_id'], 'test_user_id')
        
        # after the user deleted
        self.user.delete()
        response = self.client.get(
            path = self.user_detail_url, 
            HTTP_AUTHORIZATION=f"Bearer {access_token}"
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)




class AppleOauthViewTestCase(test.APITestCase):
    
    def setUp(self):
        self.client = test.APIClient()  
        self.callback_url = reverse('apple-callback')
    
    def test_callback_view_with_invalid_data(self):
        response = self.client.post(self.callback_url, data={
            'code': 'invalid_auth_code'
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.get('Content-Type'), 'application/json')
        
    def test_callback_view_without_data(self):

        # without "code" 
        response = self.client.post(self.callback_url, data={}, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # {'error' : 'code is missing'}, dict
        self.assertIn('error', response.data)
        self.assertEqual(response.data.get('error'), "code is missing")
        self.assertEqual(response.get('Content-Type'), 'application/json')

"""
    Views for testing only
"""
@decorators.api_view(['GET'])
@decorators.permission_classes([permissions.AllowAny])
def test_view(request):
    non_existing_keys = ["access_token", "token_type",]
    temp_data = ["expires_in", "refresh_token", "id_token"]
    my_dict = {
            'error' : '[' + ', '.join(non_existing_keys) + ']' + " are not included.",
            'reponse.json()' : temp_data
        }
    return Response(my_dict, status = status.HTTP_200_OK)  # Send as a real HTTP response
urlpatterns = [
    path('test-api/', test_view),  # Temporary URL for the test
]

@override_settings(ROOT_URLCONF=__name__)
class DRFResponseTest(test.APITestCase):

    def setUp(self):
        self.client = test.APIClient()
        self.data =     {
            "access_token": "test_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "test_refresh_token",
            "id_token": "test_id_token",
        }
        self.expected_keys = ["access_token", "token_type", "expires_in", "refresh_token", "id_token"]

    def test_response_with_dictionary(self):
        non_existing_keys = ["access_token", "token_type",]
        temp_data = ["expires_in", "refresh_token", "id_token"]
        my_dict = {
            'error' : '[' + ', '.join(non_existing_keys) + ']' + " are not included.",
            'reponse.json()' : temp_data
        }
        response_before_sent= Response(my_dict)  
        self.assertDictEqual(response_before_sent.data, my_dict)
        self.assertIsInstance(response_before_sent.data, dict)
        self.assertEqual(response_before_sent.get('Content-Type'), 'text/html; charset=utf-8')
        
        """
            After response.render() called, Content-Type is set automatically (usually as application/json)
            Check SimpleTemplateResponse and its subclass, DRF Response with their renderers
        """
        response_received = self.client.get(path= '/test-api/')
        self.assertDictEqual(response_received.data, my_dict)
        self.assertIsInstance(response_received.data, dict)
        self.assertEqual(response_received.get('Content-Type'), 'application/json')

    def test_key_included_as_expected(self):

        temp_data = copy.deepcopy(self.data)
        non_existing_keys = [k for k in self.expected_keys if k not in temp_data]
        self.assertEqual(len(non_existing_keys), 0)



    def test_some_key_is_not_included(self):
        temp_data = copy.deepcopy(self.data)
        self.assertEqual(temp_data.pop('id_token'), 'test_id_token')

        non_existing_keys = [k for k in self.expected_keys if k not in temp_data]
        self.assertEqual(len(non_existing_keys), 1)
        self.assertIn('id_token', non_existing_keys)

        self.assertEqual(temp_data.pop('expires_in'), 3600)
        non_existing_keys = [k for k in self.expected_keys if k not in temp_data]
        self.assertEqual(len(non_existing_keys), 2)
        self.assertIn('id_token', non_existing_keys); self.assertIn('expires_in', non_existing_keys)


        response_body = {
            'error' : ', '.join(non_existing_keys) + " are not included.",
            'reponse.json()' : temp_data
        }
        # how to emulate

        try:
            raise ValueError(response_body) # dict as arg
        except ValueError as e:
            response = Response(e.args[0], status = status.HTTP_400_BAD_REQUEST)
            # Assertions using Django TestCase methods
            self.assertIsInstance(response.data, dict)  # Assert that response.data is a dictionary
            self.assertEqual(response.data, response_body)  # Assert that the response data matches the response body
            #self.assertEqual(response.get('Content-Type'), 'application/json')
