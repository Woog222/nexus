from django.contrib import admin
from django.urls import path
from .views import (
    NexusFileDownloadAPIView, 
    NexusFileUploadAPIView, 
    NexusFileListAPIView, 
    NexusFileDeleteAPIView,
)

urlpatterns = [
    path("files/list/", NexusFileListAPIView.as_view(), name="file_list"),  # No user_id
    path("files/list/<str:user_id>/", NexusFileListAPIView.as_view(), name="user_file_list"),
    path('files/upload/', NexusFileUploadAPIView.as_view(), name="file_upload" ),
    path('files/download/<str:file_name>/', NexusFileDownloadAPIView.as_view(), name="file_download"),
    path('files/delete/<str:file_name>/', NexusFileDeleteAPIView.as_view(), name="file_delete"),
]