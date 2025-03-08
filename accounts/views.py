from django.http import QueryDict
from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from django.core.mail import send_mail

from rest_framework import (
    permissions, 
    views,
    generics,
    status,
    parsers,
    exceptions,
    viewsets,
    decorators,
    mixins,
)
from rest_framework.response import Response

import logging



from .serializers import NexusUserSerializer
from .models import NexusUserRelation, NexusUserRelationPagination


logger = logging.getLogger(__name__)



from rest_framework import mixins, viewsets



class NexusUserDetailView(generics.RetrieveUpdateAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = NexusUserSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    parser_classes = [parsers.MultiPartParser, parsers.FormParser]  # Enable file uploads
    lookup_field = 'username'
    lookup_url_kwarg = 'username'


    def update(self, request, *args, **kwargs):
        if request.user.username != self.kwargs.get('username'):
            return Response({"error": "You are not allowed to update this user."}, status=status.HTTP_403_FORBIDDEN)
        return super().update(request, *args, **kwargs)
    


class NexusUserRelationView(generics.GenericAPIView):
    """
    Block OR Follow a user
    """
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    parser_classes = [parsers.JSONParser]
    serializer_class = NexusUserSerializer
    lookup_field = 'username'
    lookup_url_kwarg = 'username'
    pagination_class = NexusUserRelationPagination

    @property
    def allowed_relation_types_for_setup(self):
        """
        Get allowed relation types
        Check NexusUserRelation.RELATION_CHOICES
        """
        return [x[1].lower() for x in NexusUserRelation.RELATION_CHOICES]


    @property
    def allowed_relation_types_for_lookup(self):
        """
        Get allowed relation types for lookup
        Check NexusUserSerializer SerializerMethodField names
        """
        return ['follower_users', 'following_users', 'blocked_users', 'reported_users']

    def get_queryset(self, user, relation_type:str, **kwargs):
        """
        Get queryset for the relation type
        """
        assert relation_type in self.allowed_relation_types_for_lookup
        UserModel = get_user_model()

        if relation_type == 'follower_users':
            return UserModel.objects.filter(
                relations_by_from_user__relation_type=NexusUserRelation.FOLLOW,
                relations_by_from_user__to_user = user
            )
        elif relation_type == 'following_users':
            return UserModel.objects.filter(
                relations_by_to_user__relation_type=NexusUserRelation.FOLLOW,
                relations_by_to_user__from_user = user
            )
        elif relation_type == 'blocked_users':
            return UserModel.objects.filter(
                relations_by_to_user__relation_type=NexusUserRelation.BLOCK,
                relations_by_to_user__from_user = user
            )
        elif relation_type == 'reported_users':
            return UserModel.objects.filter(
                relations_by_to_user__relation_type=NexusUserRelation.REPORT,
                relations_by_to_user__from_user = user
            )

            



    def get(self, request, username:str, **kwargs):
        """
        Get followers or following or block list of the user
        Query parameter: relation_type 
        """
        user = get_object_or_404(get_user_model(), username=username)
        relation_type = request.GET.get('relation_type', None)
        try:
           queryset = self.get_queryset(user, relation_type, **kwargs)
        except AssertionError:
            return Response({"error": f"Invalid Query parameter 'relation_type' ({relation_type}). Must be {self.allowed_relation_types_for_lookup}"}, status=status.HTTP_400_BAD_REQUEST)
  
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, username:str, **kwargs):
        """
        Block, Follow, Report a user
        """

        # relation_type validation
        try:
            # ['follow', 'block', 'report']
            relation_type = request.data.get('relation_type', None)
            assert relation_type in self.allowed_relation_types_for_setup
        except AssertionError:
            return Response(
                {
                "error": f"Invalid 'relation type' ({relation_type}). Must be {self.allowed_relation_types_for_setup}"
                }, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # from_user, to_user validation
        from_user = request.user
        to_user = get_object_or_404(get_user_model(), username=username)
        if from_user == to_user:
            return Response({"error": "You cannot follow or block yourself."}, status=status.HTTP_403_FORBIDDEN)

        # Create or Cancel the relation
        rel, created = NexusUserRelation.objects.get_or_create(
            from_user=from_user,
            to_user=to_user,
            relation_type=relation_type.upper()[0]
        )
        if not created: rel.delete() # cancel the relation
            

        # send email (report)
        if created and relation_type == 'report':
            logger.debug(f"send email (report) : \n{request.data}")
            logger.debug(f" {getattr(request.data, 'message', settings.EMAIL_DEFAULT_MESSSAGE)}")
            send_mail(  
                subject=f"[User Report] {to_user.username} reported by {from_user.username}", 
                message= request.data.get('message', settings.EMAIL_DEFAULT_MESSSAGE),
                from_email=settings.EMAIL_HOST_USER, 
                recipient_list=[settings.EMAIL_HOST_USER],
                fail_silently=False
            )
        
        return Response(
            {
                "from_username": from_user.username,
                "to_username": to_user.username,
                "relation_type": relation_type,
                "created": created
            }, 
            status=status.HTTP_200_OK
        )











# class AppleOauthView(views.APIView):
#    
#     permission_classes = [permissions.AllowAny]
# 
#     APPLE_DATA = {
#         'APPLE_CLIENT_ID' : settings.APPLE_CLIENT_ID,
#         'APPLE_KEY_ID' : settings.APPLE_KEY_ID,
#         'APPLE_TEAM_ID': settings.APPLE_TEAM_ID,
#         'APPLE_REDIRECT_URI' : settings.APPLE_REDIRECT_URI,
#         'APPLE_PUBLIC_KEY_URL' : settings.APPLE_PUBLIC_KEY_URL,
#         'APPLE_TOKEN_URL' : settings.APPLE_TOKEN_URL,
#         'APPLE_PRIVATE_KEY' : settings.APPLE_PRIVATE_KEY,
#     }
# 
#     def post(self, request, *args, **kwargs):
#         """
#             STEP 1. Validate the authorization grant code and get a token data
# 
#             Example of a token data : 
#             {
#                 "access_token": "a7f9eb52b7b70...",
#                 "token_type": "Bearer",
#                 "expires_in": 3600,
#                 "refresh_token": "rf5430a91dadf...",
#                 "id_token": "eyJraWQiOiJyczBNM2t...
#             } (dict)
#         """
#         auth_code = request.data.get("code")
#         if not auth_code:
#             return Response({"error": "code is missing"}, status=status.HTTP_400_BAD_REQUEST)
# 
#         try:
#             token_data = exchange_apple_auth_code(auth_code=auth_code, APPLE_DATA= self.APPLE_DATA)
#         except ValueError as e:
#             return Response(e.args[0], status=status.HTTP_400_BAD_REQUEST)
#         # The "token_data" is now ensured to have all keys commented above.
# 
#         """
#             STEP 2. Validate and decode the id_token
#         """        
#         try:
#             id_token_decoded = validate_apple_id_token(
#                 id_token = token_data.get('id_token'), 
#                 client_id=self.APPLE_DATA.get('APPLE_CLIENT_ID')
#             )
#         except ValueError as e:
#             return Response(e.args[0], status=status.HTTP_400_BAD_REQUEST)
#         # The "id_token"_decoded is now ensured to have 'sub' and 'email'.
#         """
#             STEP 3. Issue JWT tokens and update user data.
#         """
#         user_id = f"{settings.APPLE_USER_ID_PREFIX}_{id_token_decoded.get("sub")}"
#         email = id_token_decoded.get("email")
#         apple_access_token = token_data.get("access_token")
#         apple_refresh_token = token_data.get("refresh_token")
# 
#         user, created = NexusUser.objects.get_or_create(
#             user_id=user_id, 
#             defaults={
#                 "email": email,
#                 "apple_access_token": apple_access_token,
#                 "apple_refresh_token": apple_refresh_token,
#             }
#         )
# 
#         refresh = RefreshToken.for_user(user)
#         return Response({
#             "user_id" : user_id,
#             "refresh": str(refresh),
#             "access": str(refresh.access_token),
#             "created" : "yes" if created else "no",
#         }, status=status.HTTP_200_OK)
