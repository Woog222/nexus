# engine/views.py
from django.conf import settings
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
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
from accounts.models import NexusUserRelation

logger = logging.getLogger(__name__)

class NexusFileListCreateAPIView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    queryset = NexusFile.objects.all()
    serializer_class = NexusFileSerializer
    pagination_class = NexusFilePagination
    parser_classes = [parsers.MultiPartParser, parsers.FormParser]  # Allow file uploads

    def perform_create(self, serializer):
        model_file = self.request.FILES.get("model_file")  # Retrieve the uploaded file
        if not model_file:
            raise serializers.ValidationError({"model_file": "This field is required."})
        serializer.save(owner=self.request.user, model_file=model_file)
        logger.info(f"[file create] {serializer.data}")

    def get_queryset(self):
        """
        Get the queryset for the NexusFileListCreateAPIView.
        https://docs.djangoproject.com/en/5.1/topics/db/queries/#lookups-that-span-relationships
        https://docs.djangoproject.com/en/5.1/topics/db/queries/#spanning-multi-valued-relationships
        """
        queryset = super().get_queryset() # get the default queryset

        """
        Filtering based on blocked users and blocked files
        """
        # exclude files that the user has blocked directly
        # or files uploaded by users that the user has blocked
        if self.request.user and self.request.user.is_authenticated:

            # exclude files that the user has blocked
            queryset = queryset.exclude(blocked_users=self.request.user) 

            # exclude files uploaded by users that the user has blocked
            blocked_users = self.request.user.relations_by_from_user.filter(
                relation_type=NexusUserRelation.BLOCK
            ).values_list('to_user', flat=True)
            queryset = queryset.exclude(owner__in=blocked_users)

        """
        Filtering based on username query parameter (owner)
        """
        # username query parameter to filter files by owner
        username = self.request.GET.get('username', None)
        if username:
            user = get_object_or_404(get_user_model(), username=username)
            queryset = queryset.filter(owner=user)  # Files of a specific user

        """
        Filtering based on liked files
        """
        # username query parameter to filter files by owner
        liked_user_name = self.request.GET.get('liked_user_name', None)
        if liked_user_name:
            user = get_object_or_404(get_user_model(), username=liked_user_name)
            queryset = queryset.filter(liked_users=user)  # Files of a specific user

        return queryset



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

    def patch(self, request, file_name:str, *args, **kwargs):
        """
        {
            "action": "like" | "dislike" | "block" | "report"
        }
        """
        if request.data.get("action") not in self.action_map.keys():
            return response.Response({"error": f"Invalid action: {request.data.get('action')}. Must be one of: {self.action_map.keys()}"}, status=status.HTTP_400_BAD_REQUEST)

        file_obj = get_object_or_404(NexusFile, model_file = os.path.join('nexus_models', file_name))
        response_body = self.get_response_body( request, file_obj)
        logger.info(f"[file action] {response_body}")
        return response.Response(response_body, status=status.HTTP_200_OK)

    def get_response_body(self, request, file_obj):
        """
        Get the response body for the NexusFileActionsAPIView.
        """
        action = request.data.get("action")
        created = self.action_map[action](request, file_obj)
        return {
            "username": request.user.username,
            "filename": file_obj.model_file.name,
            "action": action,
            "created": created
        }

    @property
    def action_map(self):
        return {
            "like": self._like,
            "dislike": self._dislike,
            "block": self._block,
            "report": self._report
        }

    def _like(self, request, file_obj):
        created = not file_obj.liked_users.filter(id=request.user.id).exists()
        if created:
            file_obj.liked_users.add(request.user)
        else:
            file_obj.liked_users.remove(request.user)
        return created

    def _dislike(self, request, file_obj):
        created = not file_obj.disliked_users.filter(id=request.user.id).exists()
        if created:
            file_obj.disliked_users.add(request.user)
        else:
            file_obj.disliked_users.remove(request.user)
        return created

    def _block(self, request, file_obj):
        created = not file_obj.blocked_users.filter(id=request.user.id).exists()
        if created:
            file_obj.blocked_users.add(request.user)
        else:
            file_obj.blocked_users.remove(request.user)
        return created

    def _report(self, request, file_obj):
        created = not file_obj.reported_users.filter(id=request.user.id).exists()
        if created:
            file_obj.reported_users.add(request.user)
            send_mail(  
                subject=f"[File Report] {file_obj.model_file.name} reported by {request.user.username}", 
                message=request.data.get('message', settings.EMAIL_DEFAULT_MESSSAGE),
                from_email=settings.EMAIL_HOST_USER, 
                recipient_list=[settings.EMAIL_HOST_USER],
                fail_silently=False
            )
        else:
            file_obj.reported_users.remove(request.user)


        return created

