# engine/models.py
from django.db import models
from accounts.models import NexusUser 

class NexusFile(models.Model):
    name = models.CharField(max_length=255, unique=True)
    file_extension = models.CharField(max_length=16)
    owner = models.ForeignKey(NexusUser, on_delete=models.CASCADE, null=True, blank=False)  # Corrected ForeignKey field

    class Meta:
        ordering = ['name']  # Orders by name

    def __str__(self):
        return f"{self.name}.{self.file_extension}"
