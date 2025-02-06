from django.contrib import admin
from django.urls import path
from .views import FileDownloadAPIView, FileUploadAPIView, FileListAPIView, reset_ultimately, db_update

urlpatterns = [
    path('upload/', FileUploadAPIView.as_view(), name="file_upload" ),
    path('download/<str:file_name>/', FileDownloadAPIView.as_view(), name="file_download"),
    path('', FileListAPIView.as_view(), name="file_list"),
    path('reset/', reset_ultimately, name="true_reset"),
    path('db_update/', db_update, name = "db_update"),
]