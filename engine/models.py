# engine/models.py
from django.db import models
from accounts.models import NexusUser 
from django.db.models.signals import post_delete
from django.dispatch import receiver

import os, logging

logger= logging.getLogger(__name__)


def get_NexusFile_upload_path(instance, filename):
    """Generate a unique path for user profile images."""
    upload_to = 'nexus_models'
    new_filename = f'{instance.owner.user_id}__{filename}' # is it okay?
    return os.path.join(upload_to, new_filename)




class NexusFile(models.Model):
    owner = models.ForeignKey(NexusUser, on_delete=models.CASCADE, null=True, blank=False)  # Corrected ForeignKey field
    model_file = models.FileField(upload_to=get_NexusFile_upload_path, null=False, blank=False)
    likes = models.BigIntegerField(null=False, blank=False, default=0)
    views = models.BigIntegerField(null=False, blank=False, default=0)

    class Meta:
        ordering = ['views']

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