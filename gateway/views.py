import re

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Email
from .serializers import EmailSerializer
from .risk_engine import send_to_risk_engine


class EmailAPIView(APIView):

    def post(self, request):

        data = request.data

        body = data.get("body", "")

        # Extract URLs
        urls = re.findall(r'https?://\S+', body)
        data["urls"] = urls

        serializer = EmailSerializer(data=data)

        if serializer.is_valid():

            # Save email to database
            email = serializer.save()

            # Prepare response in the format Risk Engine wants
            response_data = {
                "message": "Email Stored",
                "email_id": email.id,
                "urls": urls,
                "data": serializer.data,
            }

            # Send JSON to Risk Engine API
            send_to_risk_engine(response_data)

            # Return same response to API caller
            return Response(
                response_data,
                status=status.HTTP_201_CREATED,
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )