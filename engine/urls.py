from django.contrib import admin
from django.urls import path
from .views import (
    NexusFileDownloadAPIView, 
    NexusFileUploadAPIView, 
    NexusFileListAPIView, 
    NexusFileDeleteAPIView,
    reset_ultimately, 
    db_update,
)

urlpatterns = [
    path('', NexusFileListAPIView.as_view(), name="file_list"),
    path('upload/', NexusFileUploadAPIView.as_view(), name="file_upload" ),
    path('download/<str:file_name>/', NexusFileDownloadAPIView.as_view(), name="file_download"),
    path('delete/<str:file_name>/', NexusFileDeleteAPIView.as_view(), name="file_delete"),
    
    path('reset/', reset_ultimately, name="true_reset"),
    path('db_update/', db_update, name = "db_update"),
]