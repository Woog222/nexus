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


from .models import NexusUserRelation
from engine.models import NexusFile
from .serializers import NexusUserSerializer

USER_DETAIL_URL_NAME = 'user-detail'
USER_RELATION_URL_NAME = 'user-relation'



logger = logging.getLogger(__name__)

class NexusUserManagerTests(test.APITestCase):
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




    def test_user_profile_image_default(self):
        """Test that the default profile image is set"""
        self.assertEqual(self.user.profile_image.name, "user_profile_images/default_profile.jpg")

    def test_user_liked_files(self):
        """Test the liked_files relationship"""
        nexus_file = NexusFile.objects.create(owner=self.user, model_file=SimpleUploadedFile("file.txt", b"file_content"))
        self.user.liked_files.add(nexus_file)
        self.assertIn(nexus_file, self.user.liked_files.all())
        nexus_file.delete()

class NexusUserRetrieveTests(test.APITestCase):
    """Test getting user profile"""

    def setUp(self):
        logger.debug(f'\n----------------{self._testMethodName}----------------')
        """Setup test user and authentication"""    
        self.user = get_user_model().objects.create_user(
            username="username",
            nickname="nickname",
            email="email@example.com",
            password="password123",
        )


    def tearDown(self):
        logger.debug(f'\n----------------{self._testMethodName}----------------\n')

    def test_get_user_profile_as_authenticated(self):
        """Test getting user profile as authenticated"""

        self.client.force_authenticate(user=self.user)
        response = self.client.get(reverse(USER_DETAIL_URL_NAME, kwargs={'username': self.user.username}))
        logger.debug(response.json())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('username', response.json())
        self.assertIn('nickname', response.json())
        self.assertIn('profile_image', response.json())
        self.assertIn('email', response.json())
        self.assertIn('following_users', response.json())
        self.assertIn('follower_users', response.json())
        self.assertIn('blocked_users', response.json())
        self.assertIn('reported_users', response.json())


    def test_get_user_profile_as_unauthenticated(self):
        """Test getting user profile as unauthenticated"""

        self.client.force_authenticate(user=None)
        response = self.client.get(reverse(USER_DETAIL_URL_NAME, kwargs={'username': self.user.username}))
        logger.debug(response.json())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('username', response.json())
        self.assertIn('nickname', response.json())
        self.assertIn('profile_image', response.json())
        self.assertIn('email', response.json())
        self.assertIn('following_users', response.json())
        self.assertIn('follower_users', response.json())
        self.assertIn('blocked_users', response.json())
        self.assertIn('reported_users', response.json())


class NexusUserUpdateTests(test.APITestCase):
    """Test user creation and profile updates"""

    def setUp(self):
        """Setup test user and authentication"""
        logger.debug(f'\n----------------{self._testMethodName}----------------')

        self.user = get_user_model().objects.create_user(
            username="testuser",
            nickname="Test User",
            email="testuser@example.com",
            password="password123",
            profile_image=SimpleUploadedFile("test_profile.jpg", b"test_profile_image", content_type="image/jpeg")
        )
        self.client.force_authenticate(user=self.user)
        self.update_url = reverse(USER_DETAIL_URL_NAME, kwargs={'username': self.user.username})

    def tearDown(self):
        # Check if the user exists in the database and delete it
        if self.user and get_user_model().objects.filter(id=self.user.id).exists():
            self.user.delete()

        logger.debug('\n----------------------------------------------------------\n')


    def test_update_required_fields(self):
        """Test that required fields (nickname) are required"""
        valid_image_bianry = self.get_valid_image_bianry_content()
        payload = {
            "nickname": "Updated User",
            "profile_image": SimpleUploadedFile("test_profile.jpg", valid_image_bianry, content_type="image/jpeg")
        }

        # 1. missing nickname
        temp_payload = copy.deepcopy(payload); temp_payload.pop("nickname")
        response = self.client.put(self.update_url, temp_payload, format="multipart")    
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


        # 2. missing profile_image
        temp_payload = copy.deepcopy(payload); temp_payload.pop("profile_image")
        response = self.client.put(self.update_url, temp_payload, format="multipart")    
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.nickname, "Updated User")

        # 3. missing both
        temp_payload = {}
        response = self.client.put(self.update_url, temp_payload, format="multipart")    
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST) 

        # 4. valid payload
        payload['nickname'] = "Updated User2"
        response = self.client.put(self.update_url, payload, format="multipart")    
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.nickname, "Updated User2")
        self.assertEqual(valid_image_bianry, open(self.user.profile_image.path, 'rb').read())

    def test_update_using_json_request(self):
        """Test updating user_name and email (JSON request), which is not allowed"""
        payload = {
            "nickname": "Updated User",
        }
        response = self.client.put(self.update_url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)
        self.user.refresh_from_db()
        self.assertEqual(self.user.nickname, "Test User") 
        self.assertEqual(self.user.email, "testuser@example.com") # email read only


    def test_update_readonly_fields(self):
        """Test that readonly fields are not allowed to be updated (ignored)"""
        valid_image_bianry = self.get_valid_image_bianry_content()
        payload = {
            "username": "newusername",
            "email": "updated@example.com",
            "nickname": "Updated User",
            "profile_image": SimpleUploadedFile("test_profile.jpg", valid_image_bianry, content_type="image/jpeg")
        }

        response = self.client.put(self.update_url, payload, format="multipart")    
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.username, "testuser") # username read only
        self.assertEqual(self.user.email, "testuser@example.com") # email read only
        self.assertEqual(self.user.nickname, "Updated User")
        self.assertEqual(valid_image_bianry, open(self.user.profile_image.path, 'rb').read())

    def test_update_using_patch(self):
        """Test updating nickname and profile_image (JSON request)"""
        valid_image_bianry_blue = self.get_valid_image_bianry_content(color='blue')
        valid_image_bianry_red = self.get_valid_image_bianry_content(color='red')
        payload = {
            "nickname": "Updated User",
            "profile_image": SimpleUploadedFile("test_profile.jpg", valid_image_bianry_blue, content_type="image/jpeg")
        }
        response = self.client.patch(self.update_url, payload, format="multipart")

        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.nickname, "Updated User")
        self.assertEqual(valid_image_bianry_blue, open(self.user.profile_image.path, 'rb').read())

        # 2. update profile_image
        payload = {
            "profile_image": SimpleUploadedFile("test_profile2.jpg", valid_image_bianry_red, content_type="image/jpeg")
        }
        response = self.client.patch(self.update_url, payload, format="multipart")
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(valid_image_bianry_red, open(self.user.profile_image.path, 'rb').read())
        self.assertEqual(self.user.nickname, "Updated User")

        # 3. update nickname
        payload = {
            "nickname": "Updated User 2"
        }
        response = self.client.patch(self.update_url, payload, format="multipart")
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.nickname, "Updated User 2")
        self.assertEqual(valid_image_bianry_red, open(self.user.profile_image.path, 'rb').read())


    def test_update_nickname_and_email_using_put(self):
        """Test updating user using put"""

        # put (invalid)
        payload = {
            "nickname": "Updated User", # only required field
        }
        response = self.client.put(self.update_url, payload, format="multipart") 
        self.user.refresh_from_db()

        logger.debug(response.json())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.nickname, "Updated User") 

        # put (valid)
        valid_image_bianry_green = self.get_valid_image_bianry_content(color='green')
        payload = {
            "nickname": "Updated User2",
            "profile_image": SimpleUploadedFile("test_profile.jpg", valid_image_bianry_green, content_type="image/jpeg")
        }
        response = self.client.put(self.update_url, payload, format="multipart") 
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.nickname, "Updated User2")
        self.assertEqual(valid_image_bianry_green, open(self.user.profile_image.path, 'rb').read())
        



    def test_update_invalid_profile_image(self):
        """Test updating profile image (multipart/form-data)"""
        invalid_image_binary = b"invalid_image_binary"

        temp_file = SimpleUploadedFile("new_profile.jpg", invalid_image_binary, content_type="image/jpeg")
        response = self.client.patch(self.update_url, {"profile_image": temp_file}, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # {'profile_image': [ErrorDetail(string='Upload a valid image. The file you uploaded was either not an image or a corrupted image.', code='invalid_image')]}


    def get_valid_image_bianry_content(self, color='red'):
        from io import BytesIO
        from PIL import Image
        # Create a simple valid image using PIL (e.g., a 100x100 red image)
        img = Image.new('RGB', (100, 100), color=color)
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
        self.assertEqual(valid_image_bianry, open(self.user.profile_image.path, 'rb').read())
       

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
        response = self.client.patch(self.update_url, payload, format="multipart")
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.username, response.json().get('username'))
        self.assertEqual(self.user.nickname, response.json().get('nickname'))
        self.assertEqual(self.user.email, response.json().get('email'))


        # put (invalid)
        response = self.client.put(self.update_url, payload, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST) 
        

    def test_unauthorized_access(self):
        """Test that an unauthorized user cannot update the profile"""
        self.client.force_authenticate(user=None) # remove authentication
        response = self.client.patch(self.update_url, {"nickname": "Unauthorized User"}, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        response = self.client.put(self.update_url, {"nickname": "Unauthorized User"}, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_another_user(self):
        malicious_user = get_user_model()(
            username="malicioususer",   
            nickname="Malicious User",
            email="malicioususer@example.com",
        )
        malicious_user.save()
        self.client.force_authenticate(user=malicious_user)

        response = self.client.patch(self.update_url, {"nickname": "Malicious User"}, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.put(self.update_url, {"nickname": "Malicious User"}, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

class NexusUserRelationTests(test.APITestCase): 
    """Test user relation"""

    def setUp(self):
        logger.debug(f'\n----------------{self._testMethodName}----------------')
        """Setup test user and authentication"""
        self.from_user = get_user_model().objects.create_user(
            username="fromuser",
            nickname="From User",
            email="fromuser@example.com",
            password="password123",
        )
        self.to_user = get_user_model().objects.create_user(
            username="touser",
            nickname="To User",
            email="touser@example.com",
            password="password123",
        )
        self.client.force_authenticate(user=self.from_user)

    def tearDown(self):
        logger.debug(f'\n----------------{self._testMethodName}----------------\n')

    def test_follow_user(self):
        """Test following a user"""
        follow_url = reverse(USER_RELATION_URL_NAME, kwargs={'username': self.to_user.username})
        payload = {
            'relation_type': 'follow'
        }

        response = self.client.post(follow_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json().get('message'), "fromuser followed touser.")
        self.assertTrue(self.from_user.relations_by_from_user.filter(to_user=self.to_user, relation_type=NexusUserRelation.FOLLOW).exists())
        
        # follow again
        response = self.client.post(follow_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.json())



    def test_block_user(self):
        """Test blocking a user"""  
        block_url = reverse(USER_RELATION_URL_NAME, kwargs={'username': self.to_user.username})
        payload = {
            'relation_type': 'block'
        }

        response = self.client.post(block_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json().get('message'), "fromuser blocked touser.")    
        self.assertTrue(self.from_user.relations_by_from_user.filter(to_user=self.to_user, relation_type=NexusUserRelation.BLOCK).exists())

        # block again
        response = self.client.post(block_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.json())

    def test_report_user(self):
        """
        Test user report
        """
        reporter = self.from_user
        malicious_user = self.to_user
        self.client.force_authenticate(user=reporter)

        payload = {
            'relation_type': 'report'
        }
        report_url = reverse(USER_RELATION_URL_NAME, kwargs={'username': malicious_user.username})
        response = self.client.post(report_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json().get('message'), f"{reporter.username} reported {malicious_user.username}.")


    def test_invalid_relation_type(self):
        """Test invalid relation type"""
        invalid_relation_url = reverse(USER_RELATION_URL_NAME, kwargs={'username': self.to_user.username})
        payload = {
            'relation_type': 'invalid'
        }

        response = self.client.post(invalid_relation_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.json())

    def test_non_existing_user(self):
        """Test non-existing user"""
        non_existing_user_url = reverse(USER_RELATION_URL_NAME, kwargs={'username': 'non_existing_user'})
        payload = {
            'relation_type': 'follow'
        }

        response = self.client.post(non_existing_user_url, payload, format='json')
        logger.debug(response.json())
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)




class NexusUserComprehensiveAPITests(test.APITestCase):
    """
    Comprehensive test for NexusUser API
    """

    def setUp(self):
        logger.debug(f'\n-------------------------------{self._testMethodName}-----------------------------------\n')
        """Setup test user and authentication"""

        self.users = [
            get_user_model().objects.create_user(
                username=f"username{i}",
                nickname=f"nickname{i}",
                email=f"email{i}@example.com",
                password="password123"
            )
            for i in range(5)
        ] # users

    def tearDown(self):
        for user in self.users:
            user.delete()

        logger.debug(f'\n--------------------------------{self._testMethodName}-----------------------------------\n')

    def test_user_followers(self):
        """
        Test user followers
        user0 is followed by user1 ~ user 4
        """

        # follow user0 from user1 ~ user4
        for i in range(1, 5):
            follow_url = reverse(USER_RELATION_URL_NAME, kwargs={'username': self.users[0].username })
            payload = {
                'relation_type': 'follow'
            }
            self.client.force_authenticate(user=self.users[i])
            response = self.client.post(follow_url, payload, format='json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.json().get('message'), f"{self.users[i].username} followed {self.users[0].username}.")

        follower_users_url = f"{reverse('user-relation', kwargs={'username': self.users[0].username})}?relation_type=follower_users"
        response = self.client.get(reverse(USER_DETAIL_URL_NAME, kwargs={'username': self.users[0].username}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn( follower_users_url, response.json().get('follower_users') )

        response = self.client.get(follower_users_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json().get('count'), 4)
        for user_profile in response.json().get('results'):
            self.assertIn(user_profile.get('username'), [self.users[i].username for i in range(1, 5)])
       
    def test_user_following(self):
        """
        Test user following
        user0 is following user1 ~ user 4
        """ 

        for i in range(1, 5):
            follow_url = reverse(USER_RELATION_URL_NAME, kwargs={'username': self.users[i].username })
            payload = {
                'relation_type': 'follow'
            }
            self.client.force_authenticate(user=self.users[0])
            response = self.client.post(follow_url, payload, format='json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.json().get('message'), f"{self.users[0].username} followed {self.users[i].username}.")

        following_users_url = f"{reverse('user-relation', kwargs={'username': self.users[0].username})}?relation_type=following_users"
        response = self.client.get(reverse(USER_DETAIL_URL_NAME, kwargs={'username': self.users[0].username}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn( following_users_url, response.json().get('following_users') )

        response = self.client.get(following_users_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json().get('count'), 4)
        for user_profile in response.json().get('results'):
            self.assertIn(user_profile.get('username'), [self.users[i].username for i in range(1, 5)])


    def test_user_blocked_users(self):
        """
        Test user blocked users
        user0 is blocking user1 ~ user 4
        """

        for i in range(1, 5):
            block_url = reverse(USER_RELATION_URL_NAME, kwargs={'username': self.users[i].username })
            payload = {
                'relation_type': 'block'
            }
            self.client.force_authenticate(user=self.users[0])
            response = self.client.post(block_url, payload, format='json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.json().get('message'), f"{self.users[0].username} blocked {self.users[i].username}.")

        blocked_users_url = f"{reverse('user-relation', kwargs={'username': self.users[0].username})}?relation_type=blocked_users"
        response = self.client.get(reverse(USER_DETAIL_URL_NAME, kwargs={'username': self.users[0].username}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn( blocked_users_url, response.json().get('blocked_users') )

        response = self.client.get(blocked_users_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json().get('count'), 4)
        for user_profile in response.json().get('results'):
            self.assertIn(user_profile.get('username'), [self.users[i].username for i in range(1, 5)])

    def test_user_reported_users(self):
        """
        Test user reported users
        user0 is reporting user1 ~ user 4
        """ 

        for i in range(1, 5):   
            report_url = reverse(USER_RELATION_URL_NAME, kwargs={'username': self.users[i].username })
            payload = {
                'relation_type': 'report'
            }
            self.client.force_authenticate(user=self.users[0])
            response = self.client.post(report_url, payload, format='json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.json().get('message'), f"{self.users[0].username} reported {self.users[i].username}.")

        reported_users_url = f"{reverse('user-relation', kwargs={'username': self.users[0].username})}?relation_type=reported_users"
        response = self.client.get(reverse(USER_DETAIL_URL_NAME, kwargs={'username': self.users[0].username}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn( reported_users_url, response.json().get('reported_users') )

        response = self.client.get(reported_users_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json().get('count'), 4)
        for user_profile in response.json().get('results'):
            self.assertIn(user_profile.get('username'), [self.users[i].username for i in range(1, 5)])




