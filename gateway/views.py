import re

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView


from .models import Email
from .serializers import EmailSerializer

class EmailAPIView(APIView):

    def post(self, request):

        data = request.data

        body = data.get("body", "")

        urls = re.findall(r'https?://\S+', body)

        data["urls"] = urls

        serializer = EmailSerializer(data=data)

        if serializer.is_valid():

            email = serializer.save()

            return Response({
                "message": "Email Stored",
                "email_id": email.id,
                "urls": urls,
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)