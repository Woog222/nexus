# engine/tests.py
from django.urls import reverse
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from .models import NexusFile
from accounts.models import NexusUser

import os, logging, base64

logger = logging.getLogger(__name__)

class FileUploadDownloadTestCase(APITestCase):

    def setUp(self):
        """Setup any initial data or files for the test."""
        self.client = APIClient()
        self.upload_url = reverse('file_upload') 
        self.download_url = reverse('file_download', kwargs={'file_name': 'test_toy_drummer.usdz'}) 
        self.list_api_url = reverse('file_list')

        self.test_file_binary_content = b"dummy_content"
        self.test_file_name = "test_toy_drummer"
        self.test_file_extension = "usdz"
        self.test_file_uploaded_path = os.path.join(settings.BASE_DIR, 'repository', 'test_toy_drummer.usdz')

         
        self.user = get_user_model().objects.create_user(
            user_id="test_user_id",
            email="test_email@gmail.com",
            user_name= "test_user_name" 
        )
        self.user.save()

        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)
        self.refresh_token = str(refresh)


    def test_urls(self):
        self.assertEqual(self.upload_url, "/engine/upload/")
        self.assertEqual(self.download_url, "/engine/download/test_toy_drummer.usdz/")
        self.assertEqual(self.list_api_url, "/engine/")

    def test_base64_functionality(self):
        encoded_string = base64.b64encode(self.test_file_binary_content).decode("utf-8")
        decoded_string = base64.b64decode(encoded_string).decode("utf-8")
        self.assertEqual(decoded_string, self.test_file_binary_content.decode("utf-8"))
        self.assertEqual(decoded_string.encode(), self.test_file_binary_content)

    def test_file_upload_and_download(self):
        # Upload the file
        payload = {
            'name': self.test_file_name,
            'file_extension': self.test_file_extension,
            'file_content': base64.b64encode(self.test_file_binary_content).decode("utf-8")
        }
        response = self.client.post(
            self.upload_url, 
            data=payload,  # APIClient automatically encodes to JSON
            format="json",   # Ensures content_type="application/json"
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}"
        )
        
        # Assert that the upload was successful
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(f'File {self.test_file_name}.{self.test_file_extension} uploaded successfully.', response.json()['message'])
        self.assertEqual(NexusFile.objects.all().filter(name = "test_toy_drummer").count(), 1)
        uploaded_file = NexusFile.objects.get(name = "test_toy_drummer")
        self.assertEqual(uploaded_file.owner, self.user)

        # Now, test the file download
        response = self.client.get(self.download_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.getvalue(), self.test_file_binary_content)
        


    def test_name_duplicate_test(self):
        """
            Test the uniqueness constraint of name column
        """
        # Upload the file once
        payload = {
            'name': self.test_file_name,
            'file_extension': self.test_file_extension,
            'file_content': base64.b64encode(self.test_file_binary_content).decode("utf-8")
        }
        response = self.client.post(
            path=self.upload_url, 
            data=payload,  # APIClient automatically encodes to JSON
            format="json",   # Ensures content_type="application/json"
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Upload the same file with the same name 
        response = self.client.post(
            path= self.upload_url, 
            data=payload,  # APIClient automatically encodes to JSON
            format="json",   # Ensures content_type="application/json"
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.json()['error'], f"A record with name '{self.test_file_name}.{self.test_file_extension}' already exists, violating uniqueness constraint.")
        if os.path.exists(self.test_file_uploaded_path):
            os.remove(self.test_file_uploaded_path)

            
            
    def test_list_api(self):
        """
            Test LIST API
        """
        # Upload files and prepare expected data
        file_name_list = ["name1", "name2", "name3"]
        extension_list = ["usdz", "hwp", "pdf"]
        expected_files = [f"{name}.{ext}" for name, ext in zip(file_name_list, extension_list)]

        for file_name, extension in zip(file_name_list, extension_list):
            payload = {
                'name': file_name,
                'file_extension': extension,
                'file_content': base64.b64encode(self.test_file_binary_content).decode("utf-8")
            }
            response = self.client.post(
                path= self.upload_url, 
                data=payload,  # APIClient automatically encodes to JSON
                format="json",   # Ensures content_type="application/json"
                HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
            )

        # Test the list API
        response = self.client.get(self.list_api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response_data = response.json()
        self.assertDictEqual(
            response_data,
            {
                "count": len(expected_files),
                "next": None,
                "previous": None,
                "results": expected_files,
            },
        )

        # clean up
        for file_name in expected_files:
            file_path = os.path.join("repository", file_name)
            os.remove(file_path)
        
    def tear_down():
        if os.path.exists(self.test_file_uploaded_path):
            os.remove(self.test_file_uploaded_path)
        else:
            logger.info("test file uploaded path does not exist.")
