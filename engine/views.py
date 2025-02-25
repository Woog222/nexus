# engine/views.py
from django.conf import settings
from rest_framework import (
    decorators,
    parsers,
    generics,
    status,
    views,
    exceptions,
    permissions,
    pagination,
    response,
    serializers
)


import os, logging, base64

from .serializers import NexusFileSerializer
from .models import NexusFile

logger = logging.getLogger(__name__)

class NexusFileUploadAPIView(generics.CreateAPIView):
    queryset = NexusFile.objects.all()
    serializer_class = NexusFileSerializer
    permission_classes = [permissions.IsAuthenticated]  # Ensure only authenticated users can upload
    parser_classes = [parsers.MultiPartParser, parsers.FormParser]  # Allow file uploads

    def perform_create(self, serializer):

        logger.debug(self.request.headers)
        logger.debug(self.request.data)
        

        model_file = self.request.FILES.get("model_file")  # Retrieve the uploaded file
        if not model_file:
            raise serializers.ValidationError({"model_file": "This field is required."})

        serializer.save(owner=self.request.user, model_file=model_file)  # Explicitly pass model_file


class NexusFileDeleteAPIView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]  

    def get_object(self):
        """Retrieve the file by name and ensure the user owns it."""
        file_name = self.kwargs.get("file_name")  
        authenticated_user = self.request.user

        try:
            obj = NexusFile.objects.get(model_file = os.path.join('nexus_models', file_name))  
        except NexusFile.DoesNotExist:
            raise exceptions.NotFound("File not found.")
        
        if obj.owner != authenticated_user:
            raise exceptions.PermissionDenied("You do not have permission to delete this file.")

        return obj


    def delete(self, request, *args, **kwargs):
        """Handle DELETE request for NexusFile."""
        instance = self.get_object()
        self.perform_destroy(instance)
        return response.Response({"message": f"File '{str(instance)}' deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


class FilePagination(pagination.PageNumberPagination):
    page_size = 10  # Default number of items per page
    page_size_query_param = 'page_size'  # Allows clients to set a custom page size
    max_page_size = 100  # Maximum items per pages

class NexusFileListAPIView(generics.ListAPIView):
    permission_classes = [permissions.AllowAny]
    queryset = NexusFile.objects.all()
    serializer_class = NexusFileSerializer
    pagination_class = FilePagination

    def get_queryset(self):
        username = self.kwargs.get("username", None)
        if username:
            return NexusFile.objects.filter(owner__username=username)  # Files of a specific user
        return NexusFile.objects.all()  # Return all files if no user_id

class NexusFileDownloadAPIView(generics.RetrieveAPIView):
    queryset = NexusFile.objects.all()
    serializer_class = NexusFileSerializer
    permission_classes = [permissions.AllowAny]

    def get_object(self):
        file_name = self.kwargs.get("file_name")
        name = os.path.join('nexus_models', file_name)
        return self.queryset.get(model_file = name)

@decorators.api_view(['PATCH'])
@decorators.permission_classes([permissions.IsAuthenticated])
def like_view(request, file_name):

    obj = NexusFile.objects.get(model_file = os.path.join('nexus_models', file_name))

    user = request.user # authenticated user
    user.liked_files.add(obj)


    return response.Response({'return' : f'{user} liked {obj}.'}, status = status.HTTP_200_OK)  # Send as a real HTTP response.Response

@decorators.api_view(['PATCH'])
@decorators.permission_classes([permissions.IsAuthenticated])
def like_cancel_view(request, file_name):

    obj = NexusFile.objects.get(model_file = os.path.join('nexus_models', file_name))
    user = request.user # authenticated user
    user.liked_files.remove(obj)

    return response.Response({'return' : f'{file_name} like canceld.'}, status = status.HTTP_200_OK)  # Send as a real HTTP response

@decorators.api_view(['PATCH'])
@decorators.permission_classes([permissions.AllowAny])
def click_view(request, file_name):

    obj = NexusFile.objects.get(model_file = os.path.join('nexus_models', file_name))
    obj.views += 1
    obj.save()
    
    return response.Response({'return' : f'{file_name} view count added.'}, status = status.HTTP_200_OK)  # Send as a real HTTP response