# engine/tests.py
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.exceptions import ValidationError
from django.urls import path, reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken

import logging, requests, json, jwt, datetime, copy

from .views import AppleOauthView
from .models import NexusUser
from .serializers import NexusUserSerializer

logger = logging.getLogger(__name__)


class NexusUserManagerTests(TestCase):
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


class NexusUserAPITestCase(APITestCase):
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

        expected_data = NexusUserSerializer(self.user).data

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertDictEqual(response.json(), expected_data)

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


"""
    Views for testing only
"""
@api_view(['GET'])
@permission_classes([AllowAny])
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
class DRFResponseTest(TestCase):

    def setUp(self):
        self.client = APIClient()
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


class AppleOauthViewTestCase(APITestCase):
    
    def setUp(self):
        self.client = APIClient()  
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
class JWTTokenUtilsTest(TestCase):
    def setUp(self):
        self.user_id = "test-user-123"
        self.email = "test@example.com"
        self.access_token = create_access_token(self.user_id, self.email)
        self.refresh_token = create_refresh_token(self.user_id)

    def test_create_access_token(self):
        decoded = validate_JWTtoken(self.access_token)
        self.assertEqual(decoded["user_id"], self.user_id)
        self.assertEqual(decoded["email"], self.email)
        self.assertEqual(decoded["iss"], "nexus")

    def test_create_refresh_token(self):
        decoded = validate_JWTtoken(self.refresh_token)
        self.assertEqual(decoded["user_id"], self.user_id)
        self.assertEqual(decoded["iss"], "nexus")

    def test_refresh_access_token(self):

        decoded = validate_JWTtoken(self.refresh_token)
        self.assertEqual(decoded['user_id'], self.user_id)

        new_access_token = create_access_token(user_id=decoded['user_id'], email=self.email)
        decoded = validate_JWTtoken(new_access_token)
        self.assertEqual(decoded["user_id"], self.user_id)
        self.assertEqual(decoded["email"], self.email)
        self.assertEqual(decoded["iss"], "nexus")

    def test_whether_access_token_exp_set_correctly(self):
        now = int(timezone.now().timestamp())
        access_token_just_created = create_access_token(self.user_id, self.email)
        decoded = jwt.decode(access_token_just_created, settings.JWT_SECRET_KEY, algorithms=["HS256"], options={"verify_signature": False})
        
        expected_exp = now + settings.JWT_ACCESS_TOKEN_TIMEDELTA.total_seconds()
        exp = decoded.get("exp")
        iat = decoded.get("iat")
        
        # Ensure expiration is correctly set
        self.assertAlmostEqual(exp, expected_exp, delta=5)  #
        self.assertAlmostEqual(iat, now, delta=5)
        self.assertEqual(exp, iat + settings.JWT_ACCESS_TOKEN_TIMEDELTA.total_seconds())
        

    def test_whether_refresh_token_exp_set_correctly(self):
        now = int(timezone.now().timestamp())
        refresh_token_just_created = create_refresh_token(self.user_id)
        decoded = jwt.decode(refresh_token_just_created, settings.JWT_SECRET_KEY, algorithms=["HS256"], options={"verify_signature": False})
        
        expected_exp = now + settings.JWT_REFRESH_TOKEN_TIMEDELTA.total_seconds()
        exp = decoded.get("exp")
        iat = decoded.get("iat")
        
        # Ensure expiration is correctly set
        self.assertAlmostEqual(exp, expected_exp, delta=5)  #
        self.assertAlmostEqual(iat, now, delta=5)
        self.assertEqual(exp, iat + settings.JWT_REFRESH_TOKEN_TIMEDELTA.total_seconds())


    def test_expired_access_token(self):
        now_datetime = timezone.now()
        expired_payload = {
            "user_id": self.user_id,
            "email": self.email,
            "exp": int( (now_datetime - datetime.timedelta(seconds=1)).timestamp() ),
            "iat": int( now_datetime.timestamp() ),
            "iss": "nexus"
        }
        expired_token = jwt.encode(expired_payload, settings.JWT_SECRET_KEY, algorithm="HS256")

        with self.assertRaises(jwt.ExpiredSignatureError):
            validate_JWTtoken(expired_token)

    def test_expired_refresh_token(self):
        now_datetime = timezone.now()
        expired_payload = {
            "user_id": self.user_id,
            "exp": int( (now_datetime - datetime.timedelta(seconds=1)).timestamp() ),
            "iat": int( now_datetime.timestamp() ),
            "iss": "nexus"
        }
        expired_token = jwt.encode(expired_payload, settings.JWT_SECRET_KEY, algorithm="HS256")

        with self.assertRaises(jwt.ExpiredSignatureError):
            validate_JWTtoken(expired_token)

    def make_tampered_token(self, token:str):

        header_base64, payload_base64, signature_base64 = token.split('.')
        tampered_tokens = []

        # 1. Modify the last character in the payload
        tampered_payload = f"{payload_base64[:-1]}{'A' if payload_base64[-1] != 'A' else 'B'}"
        tampered_tokens.append(f"{header_base64}.{tampered_payload}.{signature_base64}")

        # 2. Modify the last character in the header
        tampered_header = f"{header_base64[:-1]}{'A' if header_base64[-1] != 'A' else 'B'}"
        tampered_tokens.append(f"{tampered_header}.{payload_base64}.{signature_base64}")

        # 3. Modify the signature by changing the first character
        tampered_signature = f"{'X' if signature_base64[0] != 'X' else 'Y'}{signature_base64[1:]}"
        tampered_tokens.append(f"{header_base64}.{payload_base64}.{tampered_signature}")

        # 4. Remove the signature completely
        tampered_tokens.append(f"{header_base64}.{payload_base64}.")

        # 5. Change the order
        tampered_tokens.append(f"{payload_base64}.{header_base64}.{signature_base64}")

        # 6. Use an tampered signature
        tampered_tokens.append(f"{header_base64}.{payload_base64}.tampered_signature")

        # 7. Use a totally invalid token
        tampered_tokens.append('invalid.token.string')

        return tampered_tokens


    def test_tampered_tokens(self):
        # access token
        tampered_tokens = self.make_tampered_token(self.access_token)
        for tampered_token in tampered_tokens:
            with self.assertRaises(jwt.InvalidTokenError):
                validate_JWTtoken(tampered_token)

        # refresh token
        tampered_tokens = self.make_tampered_token(self.refresh_token)
        for tampered_token in tampered_tokens:
            with self.assertRaises(jwt.InvalidTokenError):
                validate_JWTtoken(tampered_token)
"""

"""
class JWTAuthorizationAPITestCase(APITestCase):
    def setUp(self):
        self.user_id = "test-user-123"
        self.email = "test@example.com"
        
        # Create the user in the database
        self.user = NexusUser(user_id=self.user_id, email=self.email)
        self.user.save()
        self.assertTrue(NexusUser.objects.filter(user_id=self.user_id).exists())
        
        # Create a refresh token using the user data
        self.refresh_token = create_refresh_token(self.user_id)
        self.url = "/accounts/auth/refresh/"

    def test_refresh_token_success(self):

        response = self.client.post(self.url, {"refresh_token": self.refresh_token}, format="json")

        logger.debug(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access_token", response.json())

    def test_missing_refresh_token(self):

        response = self.client.post(self.url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(response.data, { 'error': 'Refresh token is required' })

    def test_invalid_refresh_token(self):

        response = self.client.post(self.url, {"refresh_token": "invalid_token"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertDictEqual(response.data, {'error': 'Invalid refresh token'})

    def test_expired_refresh_token(self):
        now_datetime = timezone.now()
        expired_payload = {
            "user_id": self.user_id,
            "exp": int( (now_datetime - datetime.timedelta(seconds=1)).timestamp() ),
            "iat": int( now_datetime.timestamp() ),
            "iss": "nexus"
        }
        expired_token = jwt.encode(expired_payload, settings.JWT_SECRET_KEY, algorithm="HS256")
        response = self.client.post(self.url, {"refresh_token" : expired_token}, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertDictEqual(response.data, {'error': 'Refresh token has expired'})
"""
