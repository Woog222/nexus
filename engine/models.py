# engine/models.py
from django.db import models, transaction
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from rest_framework import pagination
import os, logging

logger= logging.getLogger(__name__)


def get_NexusFile_upload_path(instance, filename):
    """Generate a unique path for user profile images."""
    upload_to = 'nexus_models'
    new_filename = f'{instance.owner.username}__{filename}'
    return os.path.join(upload_to, new_filename)




class NexusFile(models.Model):
    owner = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, null=True, blank=False)  # Corrected ForeignKey field
    model_file = models.FileField(upload_to=get_NexusFile_upload_path, null=False, blank=False)
    views = models.BigIntegerField(null=False, blank=False, default=0)

    liked_users = models.ManyToManyField(get_user_model(), related_name='liked_files')
    disliked_users = models.ManyToManyField(get_user_model(), related_name='disliked_files')
    blocked_users = models.ManyToManyField(get_user_model(), related_name='blocked_files')

    class Meta:
        ordering = ['-views']


    
    @transaction.atomic
    def add_view(self):
        self.views = models.F('views') + 1
        self.save(update_fields=['views'])
        self.refresh_from_db()

    def __str__(self):
        return f"{os.path.basename(self.model_file.name)}"

@receiver(post_delete, sender=NexusFile)
def delete_nexus_file(sender, instance, **kwargs):
    """Ensure file deletion when NexusFile is deleted."""
    if instance.model_file:
        file_path = instance.model_file.path
        if os.path.isfile(file_path):
            logger.info(f"Deleting file: {file_path}")
            os.remove(file_path)
    logger.info(f"{str(instance)} instance is deleted.")

class NexusFilePagination(pagination.PageNumberPagination):
    page_size = 10  # Default number of items per page
    page_size_query_param = 'page_size'  # Allows clients to set a custom page size
    max_page_size = 100  # Maximum items per pages
