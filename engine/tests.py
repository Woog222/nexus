# engine/tests.py
from django.urls import reverse
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework import (
    status,
    test,
)
from rest_framework_simplejwt.tokens import RefreshToken

from .models import NexusFile

import os, logging, base64, inspect

logger = logging.getLogger(__name__)

class NexusFileAPITestCase(test.APITestCase):
    
    def setUp(self):
        """Create a test user and authenticate them."""
        logger.debug(f"\n\n-----------------------------{self._testMethodName}-----------------------------\n\n")
        self.authenticated_user =   get_user_model().objects.create(
            username= "user1", 
            nickname = "authenticated_user",
            email= "test1@example.com")
        self.unauthenticated_user =   get_user_model().objects.create(
            username = "user2", 
            nickname = "unauthenticated_user",
            email= "test2@example.com")
        self.client.force_authenticate(user=self.authenticated_user) # Authenticated the user 
        
        self.dummy_content = b"dummy content"
        self.test_file = SimpleUploadedFile("test_model.obj", self.dummy_content, content_type="text/plain")
        
    def tearDown(self):
        # Check if the user exists in the database and delete it
        for user in [self.authenticated_user, self.unauthenticated_user]:
            if user and get_user_model().objects.filter(id=user.id).exists():
                user.delete()

        logger.debug(f"\n\n-----------------------------{self._testMethodName}-----------------------------\n\n")

    def test_upload_file_by_authenticated_user(self):


        # Uploads the file by the authenticated user
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file},
            format   =   "multipart"
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn(self.authenticated_user.username, response.data['owner']) # url for user-profile
        self.assertEqual(NexusFile.objects.filter(owner = self.authenticated_user).count(), 1)
        self.assertEqual(NexusFile.objects.filter(owner = self.unauthenticated_user).count(), 0)

        # Compare the contents
        uploaded_file = NexusFile.objects.get(owner = self.authenticated_user)
        self.assertEqual(self.dummy_content, open(uploaded_file.model_file.path, "rb").read())
        
        logger.debug(response.data)
        logger.debug(get_user_model().objects.all()); logger.debug(NexusFile.objects.all())
  

    def test_upload_file_by_unauthenticated_user(self):
        logger.debug(get_user_model().objects.all())
        logger.debug(NexusFile.objects.all())

        # Deactivate authentication and upload the file
        self.client.force_authenticate(user=None)
        url = reverse('nexusfile-list-create')
        data = {"model_file": self.test_file}
        response = self.client.post(url, data, format="multipart")

        # Check response
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Expecting 401 Unauthorized
        logger.debug(response.data)


    def test_delete_own_file(self):
        """Test deleting a file owned by the user."""
        logger.debug(get_user_model().objects.all()); logger.debug(NexusFile.objects.all())

        nexus_file = NexusFile.objects.create(owner=self.authenticated_user, model_file=self.test_file)
        url = reverse('nexusfile-detail', kwargs = {'file_name' : os.path.basename(nexus_file.model_file.name)})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(NexusFile.objects.filter(id=nexus_file.id).exists())
        
        
    def test_delete_other_user_file(self):
        """Test that users cannot delete files they do not own."""


        other_file = NexusFile.objects.create(owner=self.unauthenticated_user, model_file=self.test_file)
        other_file.save()


        
        url = reverse('nexusfile-detail', kwargs = {'file_name' : os.path.basename(other_file.model_file.name)})
        response = self.client.delete(url)
        logger.debug(response.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        
        
        
    def test_list_files(self):
        """Test listing files."""        


        binary_contents = [f"content{i}".encode() for i in range(5)]

        for i, binary_content in enumerate(binary_contents):
            response = self.client.post(
                path      =   reverse('nexusfile-list-create'), 
                data   =   {"model_file": SimpleUploadedFile(f"test_model_{i}.obj", binary_content, content_type="text/plain")}, 
                format    =   "multipart",
            )
            logger.debug(response.data)
            self.assertIn(self.authenticated_user.username, response.data['owner']) # url for user-profile
            self.assertIn('model_file', response.data)

        response = self.client.get(path = reverse('nexusfile-list-create'))
        logger.debug(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 5)

        response = self.client.get(path = f"{reverse('nexusfile-list-create')}?username={self.authenticated_user.username}")
        logger.debug(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 5)

        response = self.client.get(path = f"{reverse('nexusfile-list-create')}?username={self.unauthenticated_user.username}")
        logger.debug(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 0)


  
        

    def test_download_file(self):
        """Test downloading a file."""


        nexus_file = NexusFile.objects.create(owner=self.authenticated_user, model_file=self.test_file)
        nexus_file.save()
        file_name = os.path.basename(nexus_file.model_file.name)
        response = self.client.get(reverse('nexusfile-detail', kwargs={'file_name': file_name}))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        logger.debug(response.data)
        self.assertEqual(response["Content-Type"], 'application/json')

        self.assertIn('owner', response.data)
        self.assertEqual(response.data['file_name'], file_name); 
        self.assertIn('likes', response.data)
        self.assertIn('views', response.data)
        self.assertIn('model_file', response.data)
        



    def test_actions_like_file(self):
        """Test liking a file."""

        nexus_file = NexusFile.objects.create(owner=self.authenticated_user, model_file=self.test_file)
        nexus_file.save()
        file_name = os.path.basename(nexus_file.model_file.name)
        url = reverse('nexusfile-actions', kwargs = {'file_name' : file_name})
        response = self.client.patch(url, data = {'action' : 'like'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(nexus_file.liked_users.count(), 1)
        self.assertEqual(nexus_file.disliked_users.count(), 0)

    def test_actions_dislike_file(self):
        """Test disliking a file."""

        nexus_file = NexusFile.objects.create(owner=self.authenticated_user, model_file=self.test_file)
        nexus_file.save()
        file_name = os.path.basename(nexus_file.model_file.name)
        url = reverse('nexusfile-actions', kwargs = {'file_name' : file_name})    
        response = self.client.patch(url, data = {'action' : 'dislike'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(nexus_file.liked_users.count(), 0)
        self.assertEqual(nexus_file.disliked_users.count(), 1)
    
    def test_actions_invalid_action(self):
        """Test invalid action."""

        nexus_file = NexusFile.objects.create(owner=self.authenticated_user, model_file=self.test_file)
        nexus_file.save()
        file_name = os.path.basename(nexus_file.model_file.name)
        url = reverse('nexusfile-actions', kwargs = {'file_name' : file_name})
        response = self.client.patch(url, data = {'action' : 'invalid'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_view_count(self):
        """Test view count."""

        nexus_file = NexusFile.objects.create(owner=self.authenticated_user, model_file=self.test_file)
        nexus_file.save()
        file_name = os.path.basename(nexus_file.model_file.name)
        url = reverse('nexusfile-detail', kwargs = {'file_name' : file_name})

        for i in range(10):
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            nexus_file.refresh_from_db()
            self.assertEqual(nexus_file.views, i + 1)
