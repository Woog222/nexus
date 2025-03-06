# accounts/urls.py
from django.urls import path, include

from .views import NexusUserDetailView, NexusUserRelationView



USER_DETAIL_URL_NAME = 'user-detail'
USER_RELATION_URL_NAME = 'user-relation'


urlpatterns = [
    path('<str:username>/', NexusUserDetailView.as_view(), name = USER_DETAIL_URL_NAME),
    path('<str:username>/relation/', NexusUserRelationView.as_view(), name = USER_RELATION_URL_NAME),
]

