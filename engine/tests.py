import os, logging
from django.test import TestCase
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.conf import settings
from rest_framework import status
from rest_framework.test import APITestCase

from .models import NexusFile


logger = logging.getLogger(__name__)

class FileUploadDownloadTestCase(APITestCase):

    def setUp(self):
        """Setup any initial data or files for the test."""
        self.upload_url = reverse('file_upload') 
        self.download_url = reverse('file_download', kwargs={'file_name': 'toy_drummer.usdz'}) 
        self.list_api_url = reverse('file_list')

        # Path for the test file you want to upload
        self.test_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data', 'toy_drummer.usdz')
        self.test_file_uploaded_path = os.path.join(settings.BASE_DIR, 'repository', 'toy_drummer.usdz')

    def test_urls(self):
        """
            Test url reverse functionality.
        """
        
        self.assertEqual(self.upload_url, "/engine/upload/")
        self.assertEqual(self.download_url, "/engine/download/toy_drummer.usdz/")
        self.assertEqual(self.list_api_url, "/engine/")


    def test_file_upload_and_download(self):
        """
            Test file upload and download functionality.
        """

        # Upload the file
        with open(self.test_file_path, 'rb') as f:
            file_data = SimpleUploadedFile('toy_drummer.usdz', f.read(), content_type='application/octet-stream')
            
            response = self.client.post(self.upload_url, {
                'name': 'toy_drummer',
                'file_extension': 'usdz',
                'file_content': file_data
            })
        
        # Assert that the upload was successful
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('File toy_drummer.usdz uploaded successfully', response.json()['message'])

        # DB Check
        self.assertEqual(NexusFile.objects.all().filter(name = "toy_drummer").count(), 1)
        
        # content check
        with open(self.test_file_path, 'rb') as x, open(self.test_file_uploaded_path, 'rb') as y:
            self.assertEqual(x.read(), y.read())

        # Now, test the file download
        response = self.client.get(self.download_url)
        
        # Assert that the download was successful
        self.assertEqual(response.status_code, 200)

        # Since the Content-Disposition header is optional, we only check if the file content matches
        with open(self.test_file_path, 'rb') as f:
            expected_content = f.read()
        self.assertEqual(response.getvalue(), expected_content)
        


    def test_name_duplicate_test(self):
        """
            Test the uniqueness constraint of name column
        """
        # Upload the file once
        with open(self.test_file_path, 'rb') as f:
            file_data = SimpleUploadedFile('toy_drummer.usdz', f.read(), content_type='application/octet-stream')
            
            response = self.client.post(self.upload_url, {
                'name': 'toy_drummer',
                'file_extension': 'usdz',
                'file_content': file_data
            })
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Upload the same file with the same name 
        with open(self.test_file_path, 'rb') as f:
            file_data = SimpleUploadedFile('toy_drummer.usdz', f.read(), content_type='application/octet-stream')
            
            response = self.client.post(self.upload_url, {
                'name': 'toy_drummer',
                'file_extension': 'usdz',
                'file_content': file_data
            })
            self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        
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

        with open(self.test_file_path, 'rb') as f:
            file_data = SimpleUploadedFile('toy_drummer.usdz', f.read(), content_type='application/octet-stream')

            for file_name, extension in zip(file_name_list, extension_list):
                response = self.client.post(self.upload_url, {
                    'name': file_name,
                    'file_extension': extension,
                    'file_content': file_data
                })
                self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Test the list API
        response = self.client.get(self.list_api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response_data = response.json()

        logger.debug(response_data)

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
