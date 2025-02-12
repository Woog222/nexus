# clean_images.py (located at the same dir with manage.py)
import os
import django
from pathlib import Path
from django.core.files.storage import default_storage

# Set up Django settings before importing models
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "nexus.settings")  # Replace with your actual project name
django.setup()

from accounts.models import NexusUser
from django.conf import settings

if __name__ == '__main__':
    # List of profile image filenames used by users
    user_profiles = ['default_profile.jpg']
    for user in NexusUser.objects.all():
        if user.profile_image:
            file_name = os.path.basename(user.profile_image.name)
            user_profiles.append(file_name)

    # print('user_profiles:', user_profiles)

    # Path to the profile images directory
    profile_images_dir = Path(settings.MEDIA_ROOT) / 'user_profile_images'

    # Iterate over files in the directory
    for file_path in profile_images_dir.iterdir():
        if file_path.is_file() and file_path.name not in user_profiles:
            # print(f"Deleting: {file_path.name}")
            default_storage.delete(str(file_path))  # Deletes the file properly

