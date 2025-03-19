# engine/tests.py
from django.urls import reverse
from django.conf import settings
from django.core import mail
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
            data     =   {"model_file": self.test_file, "title": "test title"},
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
        data = {"model_file": self.test_file, "title": "test title"}
        response = self.client.post(url, data, format="multipart")

        # Check response
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Expecting 401 Unauthorized
        logger.debug(response.data)

    def test_retrieve_file(self):
        """Test retrieving a file."""

        # 1. Upload a 
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file, "title": "test title"},
            format   =   "multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        logger.debug(f"upload response: \n{response.data}")
        self.assertIn(self.authenticated_user.username, response.data['owner']) # url for user-profile
        self.assertEqual(NexusFile.objects.filter(owner = self.authenticated_user).count(), 1)
        self.assertEqual(NexusFile.objects.filter(owner = self.unauthenticated_user).count(), 0)

        file_name = response.data['file_name']

        # 2. Retrieve the file
        response = self.client.get(reverse('nexusfile-detail', kwargs={'file_name': file_name}))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        logger.debug(f"retrieve response: \n{response.data}")
        self.assertEqual(response["Content-Type"], 'application/json')

        self.assertIn('owner', response.data)
        self.assertEqual(response.data['file_name'], file_name);
        self.assertIn('likes', response.data)
        self.assertIn('views', response.data)
        self.assertIn('model_file', response.data)
        self.assertIn('title', response.data)
        self.assertIn('description', response.data)

    def test_list_files(self):
        """Test listing files."""        

        binary_contents = [f"content{i}".encode() for i in range(5)]

        for i, binary_content in enumerate(binary_contents):
            response = self.client.post(
                path      =   reverse('nexusfile-list-create'), 
                data   =   {"model_file": SimpleUploadedFile(f"test_model_{i}.obj", binary_content, content_type="text/plain"), "title": f"test title {i}"}, 
                format    =   "multipart",
            )
            logger.debug(f"Upload response {i}: \n{response.data}")
            self.assertIn(self.authenticated_user.username, response.data['owner']) # url for user-profile
            self.assertIn('model_file', response.data)
            self.assertIn('title', response.data)
            self.assertIn('file_name', response.data)

        response = self.client.get(path = reverse('nexusfile-list-create'))
        logger.debug(f"List response: \n{response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 5)

        response = self.client.get(path = f"{reverse('nexusfile-list-create')}?owner={self.authenticated_user.username}")
        logger.debug(f"List response by {self.authenticated_user.username}: \n{response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 5)

        response = self.client.get(path = f"{reverse('nexusfile-list-create')}?owner={self.unauthenticated_user.username}")
        logger.debug(f"List response by {self.unauthenticated_user.username}: \n{response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 0)

    def test_delete_files_owned_by_user(self):
        """Test deleting a file owned by the user."""

        # 1. Upload a file
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file, "title": "test title"},
            format   =   "multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        logger.debug(f"Upload response: \n{response.data}")
        file_name = response.data['file_name']

        # 2. Delete the file
        url = reverse('nexusfile-detail', kwargs = {'file_name' : file_name})
        response = self.client.delete(url)
        logger.debug(f"Delete response: \n{response.data}")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(NexusFile.objects.filter(title = "test title").exists())
        
    def test_delete_files_owned_by_other_user(self):
        """Test that users cannot delete files they do not own."""

        # 1. Upload a file by Unauthenticated user
        self.client.force_authenticate(user=self.unauthenticated_user)
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file, "title": "test title"},
            format   =   "multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        logger.debug(f"Upload response: \n{response.data}")
        file_name = response.data['file_name']

        # 2. Delete the file by Authenticated user
        self.client.force_authenticate(user=self.authenticated_user)
        url = reverse('nexusfile-detail', kwargs = {'file_name' : file_name})
        response = self.client.delete(url)
        logger.debug(f"Delete response: \n{response.data}")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(NexusFile.objects.filter(title = "test title").count(), 1)
     
    def test_update_file_using_patch(self):
        """Test updating a file."""

        # 1. Upload a file
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file, "title": "test title", "description": "test description"},
            format   =   "multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        logger.debug(f"Upload response: \n{response.data}")
        file_name = response.data['file_name']

        # 2. Update the file using patch (only title)
        url = reverse('nexusfile-detail', kwargs = {'file_name' : file_name})
        response = self.client.patch(  
            path = url,    
            data = {"title": "updated title"},  
            format = "json"
        )
        logger.debug(f"Update response(only title): \n{response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], "updated title")
        self.assertEqual(response.data['description'], "test description")

        # 3. Update the file using patch (only description)
        response = self.client.patch(
            path = url,    
            data = {"description": "updated description"},  
            format = "json"
        )
        logger.debug(f"Update response(only description): \n{response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], "updated title")
        self.assertEqual(response.data['description'], "updated description")   
        
        # 4. Update the file using patch (both title and description)
        response = self.client.patch(
            path = url,    
            data = {"title": "updated title 2", "description": "updated description 2"},  
            format = "json"
        )
        logger.debug(f"Update response(both title and description): \n{response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], "updated title 2")
        self.assertEqual(response.data['description'], "updated description 2")
        
    def test_update_file_using_put(self):
        """Test updating a file using put."""

        # 1. Upload a file
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file, "title": "test title", "description": "test description"},
            format   =   "multipart"
        )   
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        logger.debug(f"Upload response: \n{response.data}")
        file_name = response.data['file_name']

        # 2. Update the file using put (only title)     
        url = reverse('nexusfile-detail', kwargs = {'file_name' : file_name})
        response = self.client.put(
            path = url,    
            data = {"title": "updated title"},  
            format = "json"
        )
        logger.debug(f"Update response(only title): \n{response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], "updated title")
        self.assertEqual(response.data['description'], "test description")  

        # 3. Update the file using put (only description)
        response = self.client.put(
            path = url,    
            data = {"description": "updated description"},  
            format = "json"
        )
        logger.debug(f"Update response(only description): \n{response.data}")
        # self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertEqual(response.data['title'], "updated title")   
        # self.assertEqual(response.data['description'], "updated description")  

        # 4. Update the file using put (both title and description)
        response = self.client.put(
            path = url,    
            data = {"title": "updated title 2", "description": "updated description 2"},  
            format = "json"
        )
        logger.debug(f"Update response(both title and description): \n{response.data}")
        # self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertEqual(response.data['title'], "updated title 2")
        # self.assertEqual(response.data['description'], "updated description 2")
        
        
        
    def test_actions_report_file(self):
        """Test reporting a file."""


        # 1. Upload a file
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file, "title": "test title"},
            format   =   "multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        file_name = response.data['file_name']
        nexus_file = NexusFile.objects.get(model_file__contains=file_name)

        # 2. Report the file with message
        report_url = reverse('nexusfile-actions', kwargs = {'file_name' : file_name})
        response = self.client.patch(
            path = report_url, 
            data = {'action' : 'report', 'message' : 'test message'}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(response.data['username'], self.authenticated_user.username)
        self.assertIn(file_name, response.data['filename'])
        self.assertEqual(response.data['action'], 'report')
        self.assertEqual(response.data['created'], True)
        self.assertEqual(nexus_file.reported_users.count(), 1)

        # Mail check
        logger.debug(mail.outbox[0].body)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("[File Report]", mail.outbox[0].subject)
        self.assertIn(self.authenticated_user.username, mail.outbox[0].subject)
        self.assertIn(file_name, mail.outbox[0].subject)
        self.assertEqual(mail.outbox[0].body, 'test message')
        self.assertEqual(mail.outbox[0].from_email, settings.EMAIL_HOST_USER)
        self.assertEqual(mail.outbox[0].to, [settings.EMAIL_HOST_USER])

        # 3. Cancel the report
        response = self.client.patch(
            path = report_url, 
            data = {'action' : 'report'}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(response.data['username'], self.authenticated_user.username)
        self.assertIn(file_name, response.data['filename'])
        self.assertEqual(response.data['action'], 'report')
        self.assertEqual(response.data['created'], False)
        self.assertEqual(nexus_file.reported_users.count(), 0)

        # 4. Report again (no message)
        mail.outbox = []
        response = self.client.patch(
            path = report_url, 
            data = {'action' : 'report'}  # no message
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(response.data['username'], self.authenticated_user.username)
        self.assertIn(file_name, response.data['filename'])
        self.assertEqual(response.data['action'], 'report')
        self.assertEqual(response.data['created'], True)
        self.assertEqual(nexus_file.reported_users.count(), 1)

        # Mail check
        logger.debug(mail.outbox)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("[File Report]", mail.outbox[0].subject)
        self.assertIn(self.authenticated_user.username, mail.outbox[0].subject)
        self.assertIn(file_name, mail.outbox[0].subject)
        self.assertEqual(mail.outbox[0].body, settings.EMAIL_DEFAULT_MESSSAGE)
        self.assertEqual(mail.outbox[0].from_email, settings.EMAIL_HOST_USER)
        self.assertEqual(mail.outbox[0].to, [settings.EMAIL_HOST_USER])

    
    def test_actions_block_file(self):
        """Test blocking a file."""

        # 1. Upload a file
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file, "title": "test title"},
            format   =   "multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        file_name = response.data['file_name']
        nexus_file = NexusFile.objects.get(model_file__contains=file_name)

        # 2. Block the file
        url = reverse('nexusfile-actions', kwargs = {'file_name' : file_name})
        response = self.client.patch(url, data = {'action' : 'block'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(response.data['username'], self.authenticated_user.username)
        self.assertIn(file_name, response.data['filename'])
        self.assertEqual(response.data['action'], 'block')
        self.assertEqual(response.data['created'], True)
        self.assertEqual(nexus_file.blocked_users.count(), 1)

        # 3. Cancel the block
        response = self.client.patch(url, data = {'action' : 'block'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)  
        self.assertIn(response.data['username'], self.authenticated_user.username)
        self.assertIn(file_name, response.data['filename'])
        self.assertEqual(response.data['action'], 'block')
        self.assertEqual(response.data['created'], False)
        self.assertEqual(nexus_file.blocked_users.count(), 0)

    def test_actions_like_file(self):
        """Test liking a file."""

        # 1. Upload a file
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file, "title": "test title"},
            format   =   "multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        file_name = response.data['file_name']
        nexus_file = NexusFile.objects.get(model_file__contains=file_name)

        # 2. Like the file
        url = reverse('nexusfile-actions', kwargs = {'file_name' : file_name})
        response = self.client.patch(url, data = {'action' : 'like'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(response.data['username'], self.authenticated_user.username)
        self.assertIn(file_name, response.data['filename'])
        self.assertEqual(response.data['action'], 'like')
        self.assertEqual(response.data['created'], True)
        self.assertEqual(nexus_file.liked_users.count(), 1)
        self.assertEqual(nexus_file.disliked_users.count(), 0)

        # 3. Cancel the like
        response = self.client.patch(url, data = {'action' : 'like'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(response.data['username'], self.authenticated_user.username)
        self.assertIn(file_name, response.data['filename'])
        self.assertEqual(response.data['action'], 'like')
        self.assertEqual(response.data['created'], False)
        self.assertEqual(nexus_file.liked_users.count(), 0)
        self.assertEqual(nexus_file.disliked_users.count(), 0)


    def test_actions_dislike_file(self):
        """Test disliking a file."""

        # 1. Upload a file
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file, "title": "test title"},
            format   =   "multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        file_name = response.data['file_name']
        nexus_file = NexusFile.objects.get(model_file__contains=file_name)

        # 2. Dislike the file
        url = reverse('nexusfile-actions', kwargs = {'file_name' : file_name}) 
        response = self.client.patch(url, data = {'action' : 'dislike'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(response.data['username'], self.authenticated_user.username)
        self.assertIn(file_name, response.data['filename'])
        self.assertEqual(response.data['action'], 'dislike')
        self.assertEqual(response.data['created'], True)
        self.assertEqual(nexus_file.liked_users.count(), 0)
        self.assertEqual(nexus_file.disliked_users.count(), 1)

        # 3. Cancel the dislike
        response = self.client.patch(url, data = {'action' : 'dislike'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(response.data['username'], self.authenticated_user.username)
        self.assertIn(file_name, response.data['filename'])
        self.assertEqual(response.data['action'], 'dislike')
        self.assertEqual(response.data['created'], False)
        self.assertEqual(nexus_file.liked_users.count(), 0)
        self.assertEqual(nexus_file.disliked_users.count(), 0)

    def test_actions_invalid_action(self):
        """Test invalid action."""

        # 1. Upload a file
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file, "title": "test title"},
            format   =   "multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        file_name = response.data['file_name']

        # 2. Try invalid action
        url = reverse('nexusfile-actions', kwargs = {'file_name' : file_name})
        response = self.client.patch(url, data = {'action' : 'invalid'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_view_count(self):
        """Test view count."""

        # 1. Upload a file
        response = self.client.post(
            path     =   reverse('nexusfile-list-create'),
            data     =   {"model_file": self.test_file, "title": "test title"},
            format   =   "multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        file_name = response.data['file_name']
        nexus_file = NexusFile.objects.get(model_file__contains=file_name)

        # 2. View the file 10 times
        url = reverse('nexusfile-detail', kwargs = {'file_name' : file_name})
        for i in range(10):
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            nexus_file.refresh_from_db()
            self.assertEqual(nexus_file.views, i + 1)


class NexusFileWithUserTests(test.APITestCase):
    """Test blocking a file."""

    def setUp(self):
        """Create a test user and authenticate them."""

        # owner of the file
        logger.debug(f"\n\n-----------------------------{self._testMethodName}-----------------------------\n\n")

        self.uploader1 = get_user_model().objects.create(username="uploader1", nickname="uploader1", email="uploader1@example.com")
        self.uploader2 = get_user_model().objects.create(username="uploader2", nickname="uploader2", email="uploader2@example.com")   
        self.viewer = get_user_model().objects.create(username="viewer", nickname="viewer", email="viewer@example.com")




    def tearDown(self):
        self.uploader1.delete()
        self.uploader2.delete()
        self.viewer.delete()
        logger.debug(f"\n\n-----------------------------{self._testMethodName}-----------------------------\n\n")

    def test_download_files_of_owner(self):
        """Test downloading files of the owner."""

        # Upload 5 files by uploader1
        self.client.force_authenticate(user=self.uploader1)
        for i in range(5):
            test_file = SimpleUploadedFile(f"{i}_uploader1_test_model.obj", b"dummy content", content_type="text/plain")
            response = self.client.post(
                path = reverse('nexusfile-list-create'), 
                data = {"model_file": test_file, "title": f"test title {i}"}, 
                format="multipart"
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            logger.debug(f"uploaded file {i} by uploader1: \n{response.data}")

        # Upload 5 files by uploader2   
        self.client.force_authenticate(user=self.uploader2)
        for i in range(5):
            test_file = SimpleUploadedFile(f"{i}_uploader2_test_model.obj", b"dummy content", content_type="text/plain")    
            response = self.client.post(
                path = reverse('nexusfile-list-create'), 
                data = {"model_file": test_file, "title": f"test title {i}"}, 
                format="multipart"
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            logger.debug(f"uploaded file {i} by uploader2: \n{response.data}")
        
        # Download files uploaded by the uploader1
        response = self.client.get(f"{reverse('nexusfile-list-create')}?owner={self.uploader1.username}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 5)
        logger.debug(response.data)

        sorted_files = sorted(response.data["results"], key=lambda x: x["file_name"][0])
        for i, file in enumerate(sorted_files):
            self.assertIn(reverse('user-detail', kwargs = {'username' : self.uploader1.username}), file["owner"])



        # Download files uploaded by the uploader2
        response = self.client.get(f"{reverse('nexusfile-list-create')}?owner={self.uploader2.username}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 5)
        logger.debug(response.data)

        sorted_files = sorted(response.data["results"], key=lambda x: x["file_name"][0])
        for i, file in enumerate(sorted_files):
            self.assertIn(reverse('user-detail', kwargs = {'username' : self.uploader2.username}), file["owner"])

    def test_get_file_list_excluding_blocked_files(self):
        """Test getting file list excluding blocked files."""

        # Upload 5 files by uploader1
        self.client.force_authenticate(user=self.uploader1)
        for i in range(5):
            test_file = SimpleUploadedFile(f"{i}_uploader1_test_model.obj", b"dummy content", content_type="text/plain")
            response = self.client.post(
                path = reverse('nexusfile-list-create'), 
                data = {"model_file": test_file, "title": f"test title {i}"}, 
                format="multipart"
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(NexusFile.objects.filter(owner=self.uploader1).count(), i + 1)
            logger.debug(f"uploaded files by uploader1: \n{response.data}")

        # Get filenames of the uploaded files
        response = self.client.get(f"{reverse('nexusfile-list-create')}?owner={self.uploader1.username}")
        file_names = [file["file_name"] for file in response.data["results"]]
        logger.debug(f"file names by uploader1: \n{file_names}")

        # Uploader2 blocks the 3 files uploaded by uploader1
        self.client.force_authenticate(user=self.uploader2)
        for file_name in file_names[:3]:
            url = reverse('nexusfile-actions', kwargs = {'file_name' : file_name})
            response = self.client.patch(url, data = {'action' : 'block'})
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            logger.debug(f"blocked file {file_name} by uploader2: \n{response.data}")

        # Download files when uploader2 is signed-in
        self.client.force_authenticate(user=self.uploader2)
        response = self.client.get(f"{reverse('nexusfile-list-create')}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 2)
        logger.debug(f"files get by uploader2 :\n{response.data}")

        # Download files when uploader2 is signed-out
        self.client.force_authenticate(user=None)
        response = self.client.get(f"{reverse('nexusfile-list-create')}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 5)
        logger.debug(f"files get by guest (no authentication) :\n{response.data}")

        # Download files when viewer is signed-in
        self.client.force_authenticate(user=self.viewer)
        response = self.client.get(f"{reverse('nexusfile-list-create')}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 5)
        logger.debug(f"files get by viewer :\n{response.data}")

    def test_get_file_list_excluding_blocked_files_by_uploader1(self):
        """Test getting file list excluding blocked files by uploader1."""

        # Upload 5 files by uploader1
        self.client.force_authenticate(user=self.uploader1)
        for i in range(5):
            test_file = SimpleUploadedFile(f"{i}_uploader1_test_model.obj", b"dummy content", content_type="text/plain")
            response = self.client.post(
                path = reverse('nexusfile-list-create'), 
                data = {"model_file": test_file, "title": f"test title {i}"}, 
                format="multipart"
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(NexusFile.objects.filter(owner=self.uploader1).count(), i + 1)
            logger.debug(f"uploaded files by uploader1: \n{response.data}")
        # Upload 5 files by uploader2
        self.client.force_authenticate(user=self.uploader2)
        for i in range(5):
            test_file = SimpleUploadedFile(f"{i}_uploader2_test_model.obj", b"dummy content", content_type="text/plain")
            response = self.client.post(
                path = reverse('nexusfile-list-create'), 
                data = {"model_file": test_file, "title": f"test title {i}"}, 
                format="multipart"
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(NexusFile.objects.filter(owner=self.uploader2).count(), i + 1)
            logger.debug(f"uploaded files by uploader2: \n{response.data}") 

        # Get filenames of the uploaded files
        response = self.client.get(f"{reverse('nexusfile-list-create')}?owner={self.uploader1.username}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        file_names_by_uploader1 = [file["file_name"] for file in response.data["results"]]
        response = self.client.get(f"{reverse('nexusfile-list-create')}?owner={self.uploader2.username}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        file_names_by_uploader2 = [file["file_name"] for file in response.data["results"]]

        # Viewer blocks uploader1
        self.client.force_authenticate(user=self.viewer)
        response = self.client.post(
            path = reverse('user-relation', kwargs = {'username' : self.uploader1.username}),
            data = {'relation_type' : 'block'},
            format = 'json'
        )
        logger.debug(f"viewer blocks uploader1: \n{response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Viewer get file list excluding files uploaded by uploader1
        self.client.force_authenticate(user=self.viewer)
        response = self.client.get(f"{reverse('nexusfile-list-create')}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        file_names_viewer_got = [file["file_name"] for file in response.data["results"]]
        self.assertListEqual(file_names_viewer_got, file_names_by_uploader2)
        logger.debug(f"files get by viewer :\n{response.data}")
        
    def test_get_file_list_excluding_files_blocked_both_directly_and_indirectly(self):
        """Test getting file list excluding files blocked both directly and indirectly."""

        # Upload 5 files by uploader1
        self.client.force_authenticate(user=self.uploader1)
        for i in range(5):
            test_file = SimpleUploadedFile(f"{i}_uploader1_test_model.obj", b"dummy content", content_type="text/plain")
            response = self.client.post(
                path = reverse('nexusfile-list-create'), 
                data = {"model_file": test_file, "title": f"test title {i}"}, 
                format="multipart"
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(NexusFile.objects.filter(owner=self.uploader1).count(), i + 1)
            logger.debug(f"uploaded files by uploader1: \n{response.data}")
        
        # Upload 5 files by uploader2
        self.client.force_authenticate(user=self.uploader2)
        for i in range(5):
            test_file = SimpleUploadedFile(f"{i}_uploader2_test_model.obj", b"dummy content", content_type="text/plain")
            response = self.client.post(
                path = reverse('nexusfile-list-create'), 
                data = {"model_file": test_file, "title": f"test title {i}"}, 
                format="multipart"
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(NexusFile.objects.filter(owner=self.uploader2).count(), i + 1)
            logger.debug(f"uploaded files by uploader2: \n{response.data}")

        # Get filenames of all uploaded files
        response = self.client.get(f"{reverse('nexusfile-list-create')}?owner={self.uploader1.username}")
        file_names_by_uploader1 = [file["file_name"] for file in response.data["results"]]
        response = self.client.get(f"{reverse('nexusfile-list-create')}?owner={self.uploader2.username}")
        file_names_by_uploader2 = [file["file_name"] for file in response.data["results"]]
        file_names_expected = file_names_by_uploader1 + file_names_by_uploader2
        self.assertEqual(len(file_names_by_uploader1), 5)
        self.assertEqual(len(file_names_by_uploader2), 5)
        logger.debug(f"file names by uploader1: \n{file_names_by_uploader1}")
        logger.debug(f"file names by uploader2: \n{file_names_by_uploader2}")

        # viewer blocks uploader1
        self.client.force_authenticate(user=self.viewer)
        response = self.client.post(
            path = reverse('user-relation', kwargs = {'username' : self.uploader1.username}),
            data = {'relation_type' : 'block'},
            format = 'json'
        )
        logger.debug(f"viewer blocks uploader1: \n{response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        file_names_expected = file_names_by_uploader2

        # viewer blocks 3 files uploaded by uploader2
        self.client.force_authenticate(user=self.viewer)
        for file_name in file_names_by_uploader2[:3]:
            url = reverse('nexusfile-actions', kwargs={'file_name': file_name})
            response = self.client.patch(url, data={'action': 'block'})
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            file_names_expected.remove(file_name)
            logger.debug(f"viewer blocks file {file_name}, file names expected: \n{file_names_expected}")
        self.assertEqual(len(file_names_expected), 2)
        logger.debug(f"file names expected: \n{file_names_expected}")


        # viewer get file list excluding files blocked both directly and indirectly
        self.client.force_authenticate(user=self.viewer)
        response = self.client.get(f"{reverse('nexusfile-list-create')}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        file_names_viewer_got = [file["file_name"] for file in response.data["results"]]
        self.assertListEqual(file_names_viewer_got, file_names_expected)
        logger.debug(f"files get by viewer :\n{response.data}")
    
    def test_get_liked_files(self):
        """Test getting liked files."""

        # uploader1 uploads 5 files
        self.client.force_authenticate(user=self.uploader1)
        for i in range(5):
            test_file = SimpleUploadedFile(f"{i}_uploader1_test_model.obj", b"dummy content", content_type="text/plain")   
            response = self.client.post(
                path = reverse('nexusfile-list-create'), 
                data = {"model_file": test_file, "title": f"test title {i}"}, 
                format="multipart"
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(NexusFile.objects.filter(owner=self.uploader1).count(), i + 1)
            logger.debug(f"uploaded files by uploader1: \n{response.data}")

        # Get filenames of the uploaded files
        response = self.client.get(f"{reverse('nexusfile-list-create')}?owner={self.uploader1.username}")
        file_names_by_uploader1 = [file["file_name"] for file in response.data["results"]]
        logger.debug(f"file names by uploader1: \n{file_names_by_uploader1}")


        # uploader2 likes 3 files uploaded by uploader1
        self.client.force_authenticate(user=self.uploader2)
        liked_files = file_names_by_uploader1[:3]
        for file_name in liked_files:
            response = self.client.patch(
                path = reverse('nexusfile-actions', kwargs={'file_name': file_name}), 
                data = {'action': 'like'},
                format = 'json'
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            logger.debug(f"uploader2 likes file {file_name}, file names by uploader1: \n{file_names_by_uploader1}")

        # get user profile of uploader2
        self.client.force_authenticate(user=self.uploader2)
        response = self.client.get(reverse('user-detail', kwargs={'username': self.uploader2.username}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        logger.debug(f"user profile of uploader2: \n{response.data}")
        liked_files_url = response.data['liked_files']
        response = self.client.get(liked_files_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 3)
        logger.debug(f"liked files of uploader2: \n{response.data}")

        for liked_file in response.data['results']:
            self.assertIn(liked_file['file_name'], liked_files)