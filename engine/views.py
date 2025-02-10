# file/views.py
from django.conf import settings
from django.http import HttpResponse, Http404
from django.http import FileResponse, JsonResponse
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.parsers import JSONParser
from rest_framework import status
from rest_framework.pagination import PageNumberPagination

import os, logging, base64

from .serializers import NexusFileSerializer
from .models import NexusFile

logger = logging.getLogger(__name__)

class FileUploadAPIView(APIView):
    """
    API view for uploading files.
    """
    parser_classes = [JSONParser]

    def post(self, request, *args, **kwargs):
        """
        Upload a file to the repository and save it to the DB.
        { 
            "name" : "toy_drummer",
            "file_extension" : "usdz",
            "file_content" : base64_encoded file content
        }
        """
        logger.debug("POST request received for FileUploadView.")
        logger.debug(request.headers); logger.debug(request.data)
        

        name = request.data.get('name')
        file_extension = request.data.get('file_extension')
        file_content = request.data.get('file_content')
        logger.debug(f"{name}.{file_extension} : {file_content[:10]}")

        if not name or not file_extension or not file_content:
            logger.info("Missing required parameters(name, file_extension, file_content)")
            return Response(
                {"detail": "Missing required parameters(name, file_extension, file_content)"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        
        # Check if a record with the same name already exists
        if NexusFile.objects.filter(name=name).exists():
            logger.debug(f"Record with name '{name}.{file_extension}' already exists.")
            return Response(
                {"error": f"A record with name '{name}.{file_extension}' already exists, violating uniqueness constraint."}, 
                status=status.HTTP_409_CONFLICT
            )

        try:
            file_path = os.path.join(settings.BASE_DIR, 'repository', f"{name}.{file_extension}")

            # Save the file
            # Decode Base64 back to file
            with open(file_path, 'wb') as f:
                f.write(base64.b64decode(file_content))

            # Save the metadata to the database
            a = NexusFile(name=name, file_extension=file_extension)
            a.save()
            logger.info(f"File {name}.{file_extension} uploaded successfully.")
            return Response(
                {"message": f"File {name}.{file_extension} uploaded successfully."},
                status=status.HTTP_201_CREATED
            )
        except Exception as e:
            logger.info(f"{str(e)}")
            return Response(
                {"error": f"{str(e)}"}, 
                status=status.HTTP_400_BAD_REQUEST
            )


class FileDownloadAPIView(APIView):
    """
    API view for downloading files.
    """
    def get(self, request, file_name, *args, **kwargs):
        """
        Download the requested file from the repository using FileResponse.
        """
        logger.debug(f"GET request received for FileDownloadView to download {file_name}.")
        file_path = os.path.join(settings.BASE_DIR, 'repository', file_name)

        if not os.path.exists(file_path):
            logger.debug(f"File({file_name}) not found")
            raise Http404(f"File({file_name}) not found")
        
        try:
            # Using FileResponse for efficient file handling
            response = FileResponse(open(file_path, 'rb'), as_attachment=True, filename = file_name)
            return response
        except Exception as e:
            logger.debug(f"{str(e)}")
            return Response(
                {"error": f"{str(e)}"}, 
                status=500
            )

class FilePagination(PageNumberPagination):
    page_size = 10  # Default number of items per page
    page_size_query_param = 'page_size'  # Allows clients to set a custom page size
    max_page_size = 100  # Maximum items per page

class FileListAPIView(ListAPIView):
    queryset = NexusFile.objects.all()
    serializer_class = NexusFileSerializer
    pagination_class = FilePagination
    
    

@api_view(['DELETE'])
def reset_ultimately(request):
    try:
        # Delete all NexusFile objects from the database
        NexusFile.objects.all().delete()
        
        # Define the repository directory
        repository_dir = os.path.join(settings.BASE_DIR, 'repository')
        
        # Iterate through files in the repository directory
        for filename in os.listdir(repository_dir):
            file_path = os.path.join(repository_dir, filename)
            
            # Skip directories and the `.gitkeep` file
            if os.path.isfile(file_path) and filename != '.gitkeep':
                os.remove(file_path)
        
        # Return a success response
        return Response(
            {"status": "success", "message": "All files (except .gitkeep) deleted successfully."},
            status=status.HTTP_200_OK
        )
    
    except Exception as e:
        # Handle errors and return an error response
        return Response(
            {"status": "error", "message": f"An error occurred: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        
@api_view(['PUT'])
def db_update(request):
    
    try:
        # Delete all NexusFile objects from the database
        NexusFile.objects.all().delete()
        
        repo_path = "repository"
        # Get the list of file names excluding '.gitkeep'
        file_names = [f for f in os.listdir(repo_path) if os.path.isfile(os.path.join(repo_path, f)) and f != '.gitkeep']
        
        for file_name in file_names:
            # Split the filename into name and extension
            name, extension = file_name.split(".")
            NexusFile(name=name, file_extension=extension).save()
            logger.info(f"{file_name} has been saved.")
        
        # Return a success response
        return Response(
            {"message": f"current db state : {NexusFile.objects.all()}."},
            status=status.HTTP_200_OK
        )
    
    except Exception as e:
        # Handle errors and return an error response
        return Response(
            {"status": "error", "message": f"An error occurred: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
