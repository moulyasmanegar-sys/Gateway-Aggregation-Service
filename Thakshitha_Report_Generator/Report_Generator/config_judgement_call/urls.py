from django.urls import path
from .views import receive_results

urlpatterns = [
    path("results/", receive_results, name="receive_results"),
]