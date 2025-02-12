from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.response import Response 
from rest_framework.decorators import api_view

@api_view(['GET'])
def home_view(request):
    return Response("Welcome to Nexus")

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include("accounts.urls")),
    path('', home_view, name="home_view"),
    path('engine/', include("engine.urls")),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)



