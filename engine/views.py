# engine/views.py
from django.conf import settings
from django.shortcuts import get_object_or_404
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
from .models import NexusFile, NexusFilePagination

logger = logging.getLogger(__name__)

class NexusFileListCreateAPIView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    queryset = NexusFile.objects.all()
    serializer_class = NexusFileSerializer
    pagination_class = NexusFilePagination
    parser_classes = [parsers.MultiPartParser, parsers.FormParser]  # Allow file uploads

    def get_queryset(self):
        username = self.request.GET.get('username', None)
        if username:
            return NexusFile.objects.filter(owner__username=username)  # Files of a specific user
        return NexusFile.objects.all()  # Return all files if no user_id

    def perform_create(self, serializer):

        logger.debug(self.request.headers)
        logger.debug(self.request.data)
        

        model_file = self.request.FILES.get("model_file")  # Retrieve the uploaded file
        if not model_file:
            raise serializers.ValidationError({"model_file": "This field is required."})

        serializer.save(owner=self.request.user, model_file=model_file)  # Explicitly pass model_file



class NexusFileRetrieveDestroyAPIView(generics.RetrieveDestroyAPIView):
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]  
    queryset = NexusFile.objects.all()
    serializer_class = NexusFileSerializer
    

    def get_object(self):
        """Retrieve the file by name and ensure the user owns it."""
        file_name = self.kwargs.get("file_name")  
        authenticated_user = self.request.user
        obj = get_object_or_404(NexusFile, model_file = os.path.join('nexus_models', file_name))  
        return obj

    def retrieve(self, request, *args, **kwargs):
        """Handle GET request for NexusFile."""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        instance.add_view()
        return response.Response(serializer.data)


    def destroy(self, request, *args, **kwargs):
        """Handle DELETE request for NexusFile."""
        instance = self.get_object()
        if instance.owner != request.user:
            return response.Response({"error": f"You do not have permission to delete this file."}, status=status.HTTP_403_FORBIDDEN)
        self.perform_destroy(instance)
        return response.Response({"message": f"File '{str(instance)}' deleted successfully"}, status=status.HTTP_204_NO_CONTENT)




class NexusFileActionsAPIView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        """
        {
            "action": "like" | "dislike"
        }
        """
        file_name = self.kwargs.get("file_name")
        file_obj = get_object_or_404(NexusFile, model_file = os.path.join('nexus_models', file_name))

        action = request.data.get("action")
        try:
            assert action in self.action_map.keys()
        except:
            return response.Response({"error": f"Invalid action: {action}. Must be one of: {self.action_map.keys()}"}, status=status.HTTP_400_BAD_REQUEST)

        self.action_map[action](file_obj, request.user)
        return response.Response(status=status.HTTP_200_OK)


    @property
    def action_map(self):
        return {
            "like": self._like,
            "dislike": self._dislike
        }

    def _like(self, file_obj, user):
        file_obj.liked_users.add(user)

    def _dislike(self, file_obj, user):
        file_obj.disliked_users.add(user)


