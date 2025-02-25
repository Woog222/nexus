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
from engine.models import NexusFile
from .serializers import NexusUserSerializer


logger = logging.getLogger(__name__)

class NexusUserManagerTests(TestCase):
    """Test the NexusUser model"""

    def setUp(self):
        """Set up test data for the test cases"""
        self.username = "testuser"
        self.nickname = "Test User"
        self.email = "testuser@example.com"
        self.password = "password123"
        self.user = get_user_model().objects.create_user(
            username=self.username,
            nickname=self.nickname,
            email=self.email,
            password=self.password
        )

    def test_user_creation(self):
        """Test that a user is created successfully"""
        self.assertEqual(self.user.username, self.username)
        self.assertEqual(self.user.nickname, self.nickname)
        self.assertEqual(self.user.email, self.email)
        self.assertTrue(self.user.check_password(self.password))
        self.assertTrue(self.user.is_active)
        self.assertFalse(self.user.is_staff)
        self.assertFalse(self.user.is_superuser)

    def test_user_str(self):
        """Test the string representation of the user"""
        self.assertEqual(str(self.user), self.user.get_full_name())

    def test_user_full_name(self):
        """Test the get_full_name method"""
        self.assertEqual(self.user.get_full_name(), f"{self.username} ({self.user.id})")

    def test_user_short_name(self):
        """Test the get_short_name method"""
        self.assertEqual(self.user.get_short_name(), self.username)

    def test_user_profile_image_default(self):
        """Test that the default profile image is set"""
        self.assertEqual(self.user.profile_image.name, "user_profile_images/default_profile.jpg")

    def test_user_liked_files(self):
        """Test the liked_files relationship"""
        nexus_file = NexusFile.objects.create(owner=self.user, model_file=SimpleUploadedFile("file.txt", b"file_content"))
        self.user.liked_files.add(nexus_file)
        self.assertIn(nexus_file, self.user.liked_files.all())
        nexus_file.delete()

class NexusUserAPITests(test.APITestCase):
    """Test user creation and profile updates"""

    def setUp(self):
        """Setup test user and authentication"""
        self.user = NexusUser.objects.create_user(
            username="testuser",
            nickname="Test User",
            email="testuser@example.com",
            password="password123",
            profile_image=SimpleUploadedFile("test_profile.jpg", b"test_profile_image", content_type="image/jpeg")
        )
        self.client.force_authenticate(user=self.user)
        self.update_url = reverse('user-update')

    def tearDown(self):
        # Check if the user exists in the database and delete it
        if self.user and NexusUser.objects.filter(id=self.user.id).exists():
            self.user.delete()



    def test_update_username_and_email(self):
        """Test updating user_name and email (JSON request)"""
        payload = {
            "nickname": "Updated User",
            "email": "updated@example.com"
        }
        response = self.client.patch(self.update_url, payload, format="json")

        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.nickname, "Updated User")
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

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Ensure old file is removed
        self.user.refresh_from_db()
        self.assertFalse(os.path.exists(old_image_path), "Old profile image was not deleted")

    def test_profile_image_deletion_on_instance_deletion(self):
        """Test that the old profile image is deleted when the instance is deleted."""
        old_image_path = self.user.profile_image.path  # Save old image path
        self.user.delete()
        # Ensure old file is removed
        self.assertFalse(os.path.exists(old_image_path), "Old profile image was not deleted")


    def test_update_with_invalid_field(self):
        """Test updating with an invalid field"""
        payload = {"invalid_field": "not allowed"}

        # patch (ignored)
        response = self.client.patch(self.update_url, payload, format="json")
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.username, response.json().get('username'))
        self.assertEqual(self.user.nickname, response.json().get('nickname'))
        self.assertEqual(self.user.email, response.json().get('email'))

        # put (invalid)
        response = self.client.put(self.update_url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_unauthorized_access(self):
        """Test that an unauthorized user cannot update the profile"""
        self.client.force_authenticate(user=None) # remove authentication
        response = self.client.patch(self.update_url, {"username": "Unauthorized User"}, format="json")

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
