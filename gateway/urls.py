from django.urls import path
from .views import EmailAPIView

urlpatterns = [
    path("emails/", EmailAPIView.as_view(), name="emails"),
]