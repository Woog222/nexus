from django.contrib import admin
from django.urls import path
from .views import (
    NexusFileListCreateAPIView, 
    NexusFileRetrieveDestroyAPIView,
    NexusFileActionsAPIView,
)

urlpatterns = [
    path("files/", NexusFileListCreateAPIView.as_view(), name="nexusfile-list-create"),  # query parameter: username (optional)
    path('files/<str:file_name>/', NexusFileRetrieveDestroyAPIView.as_view(), name="nexusfile-detail"),
    path('files/<str:file_name>/actions/', NexusFileActionsAPIView.as_view(), name="nexusfile-actions"),

]