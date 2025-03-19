from django.contrib import admin
from django.urls import path
from .views import (
    NexusFileListCreateAPIView, 
    NexusFileRetrieveDestroyAPIView,
    NexusFileActionsAPIView,
)

urlpatterns = [

    # query parameter: owner (optional), liked_user (optional)
    path("files/", NexusFileListCreateAPIView.as_view(), name="nexusfile-list-create"), 
    path('files/<str:file_name>/', NexusFileRetrieveDestroyAPIView.as_view(), name="nexusfile-detail"),
    path('files/<str:file_name>/actions/', NexusFileActionsAPIView.as_view(), name="nexusfile-actions"),

]