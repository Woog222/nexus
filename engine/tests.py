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
from accounts.models import NexusUser

import os, logging, base64, inspect

logger = logging.getLogger(__name__)

class NexusFileAPITestCase(test.APITestCase):
    
    def setUp(self):
        """Create a test user and authenticate them."""
        self.authenticated_user = NexusUser.objects.create(
            user_id= "user1", 
            user_name = "authenticated_user",
            email= "test1@example.com")
        self.unauthenticated_user = NexusUser.objects.create(
            user_id = "user2", 
            user_name = "unauthenticated_user",
            email= "test2@example.com")
        self.client.force_authenticate(user=self.authenticated_user) # Authenticated the user 
        
        self.dummy_content = b"dummy content"
        self.test_file = SimpleUploadedFile("test_model.obj", self.dummy_content, content_type="text/plain")
        
    def tearDown(self):
        # Check if the user exists in the database and delete it
        for user in [self.authenticated_user, self.unauthenticated_user]:
            if user and NexusUser.objects.filter(id=user.id).exists():
                user.delete()
        logger.debug(NexusUser.objects.all()); logger.debug(NexusFile.objects.all())
        logger.debug('test_end\n\n')

    def test_upload_file_by_authenticated_user(self):
        logger.debug(inspect.currentframe().f_code.co_name)
        logger.debug(NexusUser.objects.all()); logger.debug(NexusFile.objects.all())

        # Uploads the file by the authenticated user
        response = self.client.post(
            path     =   reverse('file_upload'),
            data     =   {"model_file": self.test_file},
            format   =   "multipart"
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['owner']['user_name'], self.authenticated_user.user_name)
        self.assertEqual(NexusFile.objects.filter(owner = self.authenticated_user).count(), 1)
        self.assertEqual(NexusFile.objects.filter(owner = self.unauthenticated_user).count(), 0)

        # Compare the contents
        uploaded_file = NexusFile.objects.get(owner = self.authenticated_user)
        with open(uploaded_file.model_file.path, "rb") as f:
            file_content = f.read()
        self.assertEqual(file_content, self.dummy_content)
        
        logger.debug(response.data)
        logger.debug(NexusUser.objects.all()); logger.debug(NexusFile.objects.all())
  

    def test_upload_file_by_unauthenticated_user(self):
        logger.debug(inspect.currentframe().f_code.co_name)
        logger.debug(NexusUser.objects.all())
        logger.debug(NexusFile.objects.all())

        # Deactivate authentication and upload the file
        self.client.force_authenticate(user=None)
        url = reverse('file_upload')
        data = {"model_file": self.test_file}
        response = self.client.post(url, data, format="multipart")

        # Check response
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Expecting 401 Unauthorized
        logger.debug(response.data)


    def test_delete_own_file(self):
        """Test deleting a file owned by the user."""
        logger.debug(inspect.currentframe().f_code.co_name)
        logger.debug(NexusUser.objects.all()); logger.debug(NexusFile.objects.all())

        nexus_file = NexusFile.objects.create(owner=self.authenticated_user, model_file=self.test_file)
        url = reverse('file_delete', kwargs = {'file_name' : os.path.basename(nexus_file.model_file.name)})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(NexusFile.objects.filter(id=nexus_file.id).exists())
        
        
    def test_delete_other_user_file(self):
        """Test that users cannot delete files they do not own."""
        logger.debug(inspect.currentframe().f_code.co_name)
        logger.debug(NexusUser.objects.all()); logger.debug(NexusFile.objects.all())

        other_file = NexusFile.objects.create(owner=self.unauthenticated_user, model_file=self.test_file)

        logger.debug(NexusUser.objects.all()); logger.debug(NexusFile.objects.all())
        
        url = reverse('file_delete', kwargs = {'file_name' : os.path.basename(other_file.model_file.name)})
        response = self.client.delete(url)
        logger.debug(response.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        
        
        
    def test_list_files(self):
        """Test listing files."""        
        logger.debug(inspect.currentframe().f_code.co_name)
        logger.debug(NexusUser.objects.all()); logger.debug(NexusFile.objects.all())

        binary_contents = [f"content{i}".encode() for i in range(5)]

        for i, binary_content in enumerate(binary_contents):
            response = self.client.post(
                path      =   reverse('file_upload'), 
                data   =   {"model_file": SimpleUploadedFile(f"test_model_{i}.obj", binary_content, content_type="text/plain")}, 
                format    =   "multipart",
            )
            logger.debug(response.data)
            self.assertEqual(response.data['owner']['user_id'], self.authenticated_user.user_id)
            self.assertIn('file_name', response.data)

        response = self.client.get(path = reverse('file_list'))
        logger.debug(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 5)

        response = self.client.get(path = reverse('user_file_list', kwargs = {'user_id' : self.authenticated_user.user_id}))
        logger.debug(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 5)

        response = self.client.get(path = reverse('user_file_list', kwargs = {'user_id' : self.unauthenticated_user.user_id}))
        logger.debug(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 0)


  
        

    def test_download_file(self):
        """Test downloading a file."""
        logger.debug(f"test_download_file :")
        logger.debug(NexusUser.objects.all()); logger.debug(NexusFile.objects.all())

        nexus_file = NexusFile.objects.create(owner=self.authenticated_user, model_file=self.test_file)
        file_name = os.path.basename(nexus_file.model_file.name)
        url = reverse('file_download', kwargs={'file_name': file_name})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        logger.debug(response.data)
        self.assertEqual(response["Content-Type"], 'application/json')

        self.assertDictEqual(response.data['owner'], {
            'user_id': self.authenticated_user.user_id,
            'user_name': self.authenticated_user.user_name
        })
        self.assertEqual(response.data['file_name'], file_name); 
        self.assertIn('likes', response.data)
        self.assertIn('views', response.data)
        self.assertIn('model_file', response.data)
        
